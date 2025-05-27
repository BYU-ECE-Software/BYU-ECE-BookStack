<?php

namespace BookStack\Custom;

use BookStack\Access\Saml2Service;
use Illuminate\Support\ServiceProvider;
use GuzzleHttp\Client;
use BookStack\Users\Models\Role;
use BookStack\Users\Models\User;
use BookStack\Access\RegistrationService;
use BookStack\Access\LoginService;
use BookStack\Access\GroupSyncService;

class CustomSaml2ServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->app->bind(Saml2Service::class, function ($app) {
	    // Resolve dependencies from the service container
	    try {
            $registrationService = $app->make(RegistrationService::class);
            $loginService = $app->make(LoginService::class);
            $groupSyncService = $app->make(GroupSyncService::class);
        } catch (\Exception $e) {
            \Log::error('Failed to resolve services: ' . $e->getMessage());
            throw $e;
        }

            return new class($registrationService, $loginService, $groupSyncService) extends Saml2Service {
		public function __construct(
                    RegistrationService $registrationService,
                    LoginService $loginService,
                    GroupSyncService $groupSyncService
                ) {
                    // Pass dependencies to the parent constructor
                    parent::__construct($registrationService, $loginService, $groupSyncService);
                }

                public function processLoginCallback(string $samlID, array $samlAttributes): User
                {
                    // Get the uid from the SAML response
                    //$uid = $this->getUserId($samlUser);
                    
		    \Log::info("SAML Attributes: " . json_encode($samlAttributes));
		    $byu_id = $samlAttributes['byuId'][0];
		    \Log::info("BYU ID: " . $byu_id); 

                    // Call your API to check GRO group membership
                    $groupData = $this->fetchGroupsFromApi($byu_id);

                    if (!($this->userInGroupArray($groupData, "ECE-Bookstack-Admins") || $this->userInGroupArray($groupData, "ECE-Bookstack-Editors") || $this->userInGroupArray($groupData, "ECE-Bookstack-Viewers"))) {
                        // Block the user if not in GRO group
                        abort(403, 'Access denied: You must be a member of the GRO group to log in.');
                    }

		    $userData = $this->fetchUserDataFromApi($byu_id);

		    // Get the key? idk how this works
		    $emailAttr = $this->config['email_attribute'] ?? 'email';

		    // Add email to samlAttributes for parent method
                    if (!empty($userData['basic']['byu_internal_email']['value']) && filter_var($userData['basic']['byu_internal_email']['value'], FILTER_VALIDATE_EMAIL)) {
                        $samlAttributes[$emailAttr] = [$userData['basic']['byu_internal_email']['value']];
                    } else {
                        // Fallback email to satisfy parent method
                        $samlAttributes[$emailAttr] = [$byuId . '@byu.edu'];
                        \Log::warning("No valid email from API for byuId {$byuId}, using fallback");
                    }

                    // Add display name to samlAttributes if provided
                    if (!empty($userData['basic']['preferred_name']['value'])) {
                        $samlAttributes['name'] = [$userData['basic']['preferred_name']['value']];
                    }

		    \Log::info('Modified SAML Attributes: ' . json_encode($samlAttributes));

		    $user = parent::processLoginCallback($samlID, $samlAttributes);

		    $this->updateUserAttributes($user, $userData);

		    $this->assignRolesFromApiGroups($user, $groupData);

                    // Proceed with default login/registration if authorized
                    return $user;
                }

		protected function fetchGroupsFromApi($byu_id)
		{
		    \Log::info("UID:" . $byu_id);
		    $fetchClient = new Client();
		    $apiUrl = "https://api.byu.edu/byuapi/persons/v4/$byu_id?field_sets=group_memberships";
		    $tokenUrl = "https://api.byu.edu/token";
		    $client_id = env('CLIENT_ID');
		    $client_secret = env('CLIENT_SECRET');

		    \Log::info('Client ID: ' . $client_id);
		    try {
			    $token_response = $fetchClient->post('https://api.byu.edu/token', [
			    'auth' => [$client_id, $client_secret], // Basic authentication
			    'form_params' => [
			        'grant_type' => 'client_credentials'
			    ]
       			    ]);
			    $token_response_body = $token_response->getBody()->getContents();
			    $token_data = json_decode($token_response_body, true);
			    $access_token = $token_data['access_token'];

			    $response = $fetchClient->request('GET', "https://api.byu.edu/byuapi/persons/v4/$byu_id?field_sets=group_memberships", [
	   		        'headers' => [
				    'Accept' => 'application/json',
				    'Authorization' => "Bearer $access_token",
				],
			    ]);
			    $response_body = $response->getBody()->getContents();
			    $response_body_decoded = json_decode($response_body, true);
			    return $response_body_decoded;
		    }
		    catch (\Exception $e) {
			\Log::error("API check failed for byu_id: {byu_id}: " . $e->getMessage());
			return false;
		    }
		}

		protected function fetchUserDataFromApi($byu_id){
		    $fetchClient = new Client();
                    $apiUrl = "https://api.byu.edu/byuapi/persons/v4/$byu_id?field_sets=basic";
                    $tokenUrl = "https://api.byu.edu/token";
                    $client_id = env('CLIENT_ID');
                    $client_secret = env('CLIENT_SECRET');
                    try {
                            $token_response = $fetchClient->post('https://api.byu.edu/token', [
                            'auth' => [$client_id, $client_secret], // Basic authentication
                            'form_params' => [
                                'grant_type' => 'client_credentials'
                            ]
                            ]);
                            $token_response_body = $token_response->getBody()->getContents();
                            $token_data = json_decode($token_response_body, true);
                            $access_token = $token_data['access_token'];

                            $response = $fetchClient->request('GET', "https://api.byu.edu/byuapi/persons/v4/$byu_id?field_sets=basic", [
                                'headers' => [
                                    'Accept' => 'application/json',
                                    'Authorization' => "Bearer $access_token",
                                ],
                            ]);
                            $response_body = $response->getBody()->getContents();
                            $response_body_decoded = json_decode($response_body, true);
                            return $response_body_decoded;
		    }
                    catch (\Exception $e) {
                        \Log::error("User data API check failed for BYU_ID: {byu_id}: " . $e->getMessage());
                        return false;
                    }

		}

		protected function updateUserAttributes($user, $userData)
                {
		    \Log::info('Did we even get here?');
                    // Update email if provided and valid
                    if (!empty($userData['basic']['byu_internal_email']['value']) && filter_var($userData['basic']['byu_internal_email']['value'], FILTER_VALIDATE_EMAIL)) {
                        $user->email = $userData['basic']['byu_internal_email']['value'];
                    } elseif (empty($user->email)) {
                        // Fallback if no email is provided and user has none
                        $user->email = $user->external_auth_id . '@byu.edu'; // Adjust as needed
                    }

		    \Log::info('Email: ' . $user->email);

                    // Update display name if provided
                    if (!empty($userData['basic']['preferred_name']['value'])) {
                        $user->name = $userData['basic']['preferred_name']['value'];
                    } elseif (empty($user->name)) {
                        // Fallback if no display name is provided
                        $user->name = 'User_' . $user->external_auth_id;
                    }

                    // Save changes to the user
                    $user->save();
                    \Log::info("Updated user {$user->id} with email: {$user->email}, display_name: {$user->name}");
                }

		protected function assignRolesFromApiGroups($user, $groupData)
                {
                    // Define your group-to-role mapping
                    $roleMap = [
                        'ECE-Bookstack-Admins' => 'Admin',
                        'ECE-Bookstack-Editors' => 'Editor',
                        'ECE-Bookstack-Viewers' => 'Viewer',
                        //'GRO' => 'User', // Default role for GRO members
                    ];

                    // Fetch all roles from the database
                    $roles = Role::all()->pluck('id', 'display_name')->toArray();

                    // Determine roles to assign based on API groups
                    $rolesToAssign = [];
                    foreach ($groupData['group_memberships']['values'] as $group) {
		    $group_name = $group['group_id']['value'];
		    \Log::info("Group: " . $group_name);
                        if (isset($roleMap[$group_name]) && isset($roles[$roleMap[$group_name]])) {
                            $rolesToAssign[] = $roles[$roleMap[$group_name]];
                        }
                    }

                    // Ensure at least a default role if GRO is present (this will not happen because they cannot log in in this case)
                    //if (empty($rolesToAssign) && in_array('GRO', $groups)) {
                    //    $rolesToAssign[] = $roles['User'] ?? null;
                    //}

                    // Sync roles with the user
                    if (!empty($rolesToAssign)) {
                        $user->roles()->sync($rolesToAssign);
                        \Log::info("Assigned roles to user {$user->id}: " . implode(', ', $rolesToAssign));
                    } else {
                        \Log::warning("No valid roles found for user {$user->id} with groups: " . implode(', ', $groups));
                    }
                }
		
		
                protected function userInGroupArray($jsonArray, $groupID): bool
                {
		    if (!isset($jsonArray['group_memberships']['values']) || !is_array($jsonArray['group_memberships']['values'])) {
      			return false; // Invalid or unexpected structure
  		    }

  		    foreach ($jsonArray['group_memberships']['values'] as $group) {
      			// Check if the group_id key exists and if its value matches the provided groupId
      		        if (isset($group['group_id']['value']) && $group['group_id']['value'] == $groupID) {
          		    \Log::info('MATCH!');
			    return true;
      		        }
  		    }

  		    return false; // Not found

	        }
            };
        });
    }
}
