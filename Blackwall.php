<?php
/**
 * Blackwall (BotGuard) Product Module for WISECP
 * This module allows WISECP to provision and manage BotGuard website protection services
 */
class Blackwall extends ProductModule
{
    function __construct(){
        $this->_name = __CLASS__;
        parent::__construct();
    }

    /**
     * Module Configuration Page
     */
    public function configuration()
    {
        $action = isset($_GET["action"]) ? $_GET["action"] : false;
        $action = Filter::letters_numbers($action);

        $vars = [
            'm_name'    => $this->_name,
            'area_link' => $this->area_link,
            'lang'      => $this->lang,
            'config'    => $this->config,
        ];
        return $this->get_page("configuration".($action ? "-".$action : ''),$vars);
    }

    /**
     * Save Module Configuration
     */
    public function controller_save()
    {
        // Use raw POST data to preserve the exact API key format
        $api_key = isset($_POST["api_key"]) ? $_POST["api_key"] : "";
        
        // Use Filter for the other fields
        $primary_server = Filter::init("POST/primary_server", "hclear");
        $secondary_server = Filter::init("POST/secondary_server", "hclear");

        // Log the received API key for debugging
        error_log("Received API Key: " . $api_key);

        $set_config = $this->config;

        if($set_config["settings"]["api_key"] != $api_key) 
            $set_config["settings"]["api_key"] = $api_key;
        
        if($set_config["settings"]["primary_server"] != $primary_server) 
            $set_config["settings"]["primary_server"] = $primary_server;
        
        if($set_config["settings"]["secondary_server"] != $secondary_server) 
            $set_config["settings"]["secondary_server"] = $secondary_server;

        if(Validation::isEmpty($api_key))
        {
            echo Utility::jencode([
                'status' => "error",
                'message' => $this->lang["error_api_key_required"],
            ]);
            return false;
        }

        // Save the configuration
        $this->save_config($set_config);
        
        // Log the saved API key for verification
        error_log("Saved API Key: " . $set_config["settings"]["api_key"]);

        echo Utility::jencode([
            'status' => "successful",
            'message' => $this->lang["success_settings_saved"],
        ]);

        return true;
    }
    /**
     * Get A record IPs for a domain
     * 
     * @param string $domain Domain to lookup
     * @return array Array of IPs found or default IP if lookup fails
     */
    private function get_domain_a_records($domain) {
        // Default fallback IP if DNS lookup fails
        $default_ip = ['1.23.45.67'];
        
        try {
            // Log the DNS lookup attempt
            self::save_log(
                'Product',
                $this->_name,
                'DNS Lookup',
                ['domain' => $domain],
                null,
                null
            );
            
            // Perform DNS lookup for A records
            $dns_records = @dns_get_record($domain, DNS_A);
            
            // Check if we got valid results
            if ($dns_records && is_array($dns_records) && !empty($dns_records)) {
                // Extract IPs from A records
                $ips = [];
                foreach ($dns_records as $record) {
                    if (isset($record['ip']) && !empty($record['ip'])) {
                        $ips[] = $record['ip'];
                    }
                }
                
                // Log the results
                self::save_log(
                    'Product',
                    $this->_name,
                    'DNS Lookup Results',
                    ['domain' => $domain, 'ips' => $ips],
                    null,
                    null
                );
                
                // If we found IPs, return them
                if (!empty($ips)) {
                    return $ips;
                }
            }
            
            // If lookup failed or returned no results, also try with "www." prefix
            if (strpos($domain, 'www.') !== 0) {
                $www_domain = 'www.' . $domain;
                $www_dns_records = @dns_get_record($www_domain, DNS_A);
                
                if ($www_dns_records && is_array($www_dns_records) && !empty($www_dns_records)) {
                    $www_ips = [];
                    foreach ($www_dns_records as $record) {
                        if (isset($record['ip']) && !empty($record['ip'])) {
                            $www_ips[] = $record['ip'];
                        }
                    }
                    
                    // Log the www results
                    self::save_log(
                        'Product',
                        $this->_name,
                        'DNS Lookup Results (www)',
                        ['domain' => $www_domain, 'ips' => $www_ips],
                        null,
                        null
                    );
                    
                    if (!empty($www_ips)) {
                        return $www_ips;
                    }
                }
            }
            
            // Fallback - try PHP's gethostbyname as a last resort
            $ip = gethostbyname($domain);
            if ($ip && $ip !== $domain) {
                // Log the gethostbyname result
                self::save_log(
                    'Product',
                    $this->_name,
                    'DNS Lookup (gethostbyname)',
                    ['domain' => $domain, 'ip' => $ip],
                    null,
                    null
                );
                return [$ip];
            }
            
            // If all lookups failed, return default IP
            self::save_log(
                'Product',
                $this->_name,
                'DNS Lookup Failed',
                ['domain' => $domain, 'using_default' => $default_ip],
                'DNS lookup failed, using default IP',
                null
            );
            return $default_ip;
        } catch (Exception $e) {
            // Log any errors and return default IP
            self::save_log(
                'Product',
                $this->_name,
                'DNS Lookup Error',
                ['domain' => $domain, 'error' => $e->getMessage()],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return $default_ip;
        }
    }

    /**
     * Get AAAA record IPs for a domain (IPv6)
     * 
     * @param string $domain Domain to lookup
     * @return array Array of IPv6 addresses found or default IPv6 if lookup fails
     */
    private function get_domain_aaaa_records($domain) {
        // Default fallback IPv6 if DNS lookup fails
        $default_ipv6 = ['2a01:4f8:c2c:5a72::1'];
        
        try {
            // Log the DNS lookup attempt
            self::save_log(
                'Product',
                $this->_name,
                'DNS AAAA Lookup',
                ['domain' => $domain],
                null,
                null
            );
            
            // Perform DNS lookup for AAAA records
            $dns_records = @dns_get_record($domain, DNS_AAAA);
            
            // Check if we got valid results
            if ($dns_records && is_array($dns_records) && !empty($dns_records)) {
                // Extract IPv6 addresses from AAAA records
                $ipv6s = [];
                foreach ($dns_records as $record) {
                    if (isset($record['ipv6']) && !empty($record['ipv6'])) {
                        $ipv6s[] = $record['ipv6'];
                    }
                }
                
                // Log the results
                self::save_log(
                    'Product',
                    $this->_name,
                    'DNS AAAA Lookup Results',
                    ['domain' => $domain, 'ipv6s' => $ipv6s],
                    null,
                    null
                );
                
                // If we found IPv6 addresses, return them
                if (!empty($ipv6s)) {
                    return $ipv6s;
                }
            }
            
            // If lookup failed or returned no results, also try with "www." prefix
            if (strpos($domain, 'www.') !== 0) {
                $www_domain = 'www.' . $domain;
                $www_dns_records = @dns_get_record($www_domain, DNS_AAAA);
                
                if ($www_dns_records && is_array($www_dns_records) && !empty($www_dns_records)) {
                    $www_ipv6s = [];
                    foreach ($www_dns_records as $record) {
                        if (isset($record['ipv6']) && !empty($record['ipv6'])) {
                            $www_ipv6s[] = $record['ipv6'];
                        }
                    }
                    
                    // Log the www results
                    self::save_log(
                        'Product',
                        $this->_name,
                        'DNS AAAA Lookup Results (www)',
                        ['domain' => $www_domain, 'ipv6s' => $www_ipv6s],
                        null,
                        null
                    );
                    
                    if (!empty($www_ipv6s)) {
                        return $www_ipv6s;
                    }
                }
            }
            
            // If all lookups failed, return default IPv6
            self::save_log(
                'Product',
                $this->_name,
                'DNS AAAA Lookup Failed',
                ['domain' => $domain, 'using_default' => $default_ipv6],
                'DNS AAAA lookup failed, using default IPv6',
                null
            );
            return $default_ipv6;
        } catch (Exception $e) {
            // Log any errors and return default IPv6
            self::save_log(
                'Product',
                $this->_name,
                'DNS AAAA Lookup Error',
                ['domain' => $domain, 'error' => $e->getMessage()],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return $default_ipv6;
        }
    }

    /**
     * Check if the domain DNS is correctly pointing to our protection servers
     * 
     * @param string $domain Domain to check
     * @return bool True if DNS is correctly configured, false otherwise
     */
    private function check_domain_dns_configuration($domain) {
        // Define the required DNS records for Blackwall protection
        $required_records = [
            'A' => ['49.13.161.213', '116.203.242.28'],
            'AAAA' => ['2a01:4f8:c2c:5a72::1', '2a01:4f8:1c1b:7008::1']
        ];
        
        try {
            self::save_log(
                'Product',
                $this->_name,
                'DNS Configuration Check',
                ['domain' => $domain, 'required' => $required_records],
                null,
                null
            );
            
            // Get current DNS records for the domain
            $a_records = @dns_get_record($domain, DNS_A);
            $aaaa_records = @dns_get_record($domain, DNS_AAAA);
            
            // Check if any of the required A records match
            $has_valid_a_record = false;
            foreach ($a_records as $record) {
                if (in_array($record['ip'], $required_records['A'])) {
                    $has_valid_a_record = true;
                    break;
                }
            }
            
            // Check if any of the required AAAA records match
            $has_valid_aaaa_record = false;
            foreach ($aaaa_records as $record) {
                if (in_array($record['ipv6'], $required_records['AAAA'])) {
                    $has_valid_aaaa_record = true;
                    break;
                }
            }
            
            $result = $has_valid_a_record && $has_valid_aaaa_record;
            
            self::save_log(
                'Product',
                $this->_name,
                'DNS Configuration Check Result',
                [
                    'domain' => $domain,
                    'has_valid_a' => $has_valid_a_record,
                    'has_valid_aaaa' => $has_valid_aaaa_record,
                    'result' => $result ? 'Configured correctly' : 'Not configured correctly'
                ],
                null,
                null
            );
            
            return $result;
        } catch (Exception $e) {
            self::save_log(
                'Product',
                $this->_name,
                'DNS Configuration Check Error',
                ['domain' => $domain, 'error' => $e->getMessage()],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }

    /**
     * Register the DNS check hook for a domain
     * 
     * @param string $domain Domain to check
     * @param int $order_id Order ID
     * @return bool Success status
     */
    private function register_dns_check_hook($domain, $order_id)
    {
        try {
            self::save_log(
                'Product',
                $this->_name,
                'Registering DNS Check Hook',
                ['domain' => $domain, 'order_id' => $order_id],
                null,
                null
            );
            
            // Store DNS check meta data for the hook to use
            $meta_data = [
                'domain' => $domain,
                'order_id' => $order_id,
                'check_time' => time(),
                'product_id' => 105, // Hardcoded to match the hook
                'client_id' => $this->user["id"]
            ];
            
            // Store this in a database table or file for the hook to access
            // For this example, we'll use a simple file-based approach
            $dns_check_file = sys_get_temp_dir() . '/blackwall_dns_check_' . md5($domain . $order_id) . '.json';
            file_put_contents($dns_check_file, json_encode($meta_data));
            
            self::save_log(
                'Product',
                $this->_name,
                'DNS Check Data Stored',
                ['file' => $dns_check_file, 'data' => $meta_data],
                null,
                null
            );
            
            return true;
        } catch (Exception $e) {
            self::save_log(
                'Product',
                $this->_name,
                'Error Registering DNS Check Hook',
                ['domain' => $domain, 'order_id' => $order_id],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }

    /**
     * Generate a support ticket for DNS configuration
     * This is called by the hook when DNS is not configured correctly
     * 
     * @param string $domain Domain name
     * @param int $client_id Client ID
     * @param int $order_id Order ID
     * @return bool Success status
     */
    public function create_dns_configuration_ticket($domain, $client_id, $order_id)
    {
        try {
            self::save_log(
                'Product',
                $this->_name,
                'Creating DNS Configuration Ticket',
                ['domain' => $domain, 'client_id' => $client_id, 'order_id' => $order_id],
                null,
                null
            );
            
            // Define the required DNS records for Blackwall protection
            $required_records = [
                'A' => ['49.13.161.213', '116.203.242.28'],
                'AAAA' => ['2a01:4f8:c2c:5a72::1', '2a01:4f8:1c1b:7008::1']
            ];
            
            // Get client language preference
            $client = User::getData($client_id);
            $client_lang = isset($client['lang']) ? $client['lang'] : 'en';
            
            // Get localized title
            $title_locale = [
                'en' => "DNS Configuration Required for {$domain}",
                'de' => "DNS-Konfiguration erforderlich für {$domain}",
                'fr' => "Configuration DNS requise pour {$domain}",
                'es' => "Configuración DNS requerida para {$domain}",
                'nl' => "DNS-configuratie vereist voor {$domain}",
            ];
            
            // Default to English if language not found
            $title = isset($title_locale[$client_lang]) ? $title_locale[$client_lang] : $title_locale['en'];
            
            // Create the ticket message with Markdown formatting
            $message = $this->get_dns_configuration_message($client_lang, $domain, $required_records);
            
            // Prepare ticket data
            $ticket_data = [
                'user_id' => $client_id,
                'did' => 1, // Department ID - adjust as needed
                'priority' => 2, // Medium priority
                'status' => 'process', // In progress
                'title' => $title,
                'message' => $message,
                'service' => $order_id // Order ID
            ];
            
            // Create the ticket
            if (class_exists('Models\\Tickets\\Tickets')) {
                $ticket_id = \Models\Tickets\Tickets::insert($ticket_data);
            } elseif (class_exists('Tickets')) {
                $ticket_id = Tickets::insert($ticket_data);
            } else {
                throw new Exception("Ticket system not found");
            }
            
            self::save_log(
                'Product',
                $this->_name,
                'DNS Configuration Ticket Created',
                ['ticket_id' => $ticket_id],
                null,
                null
            );
            
            return true;
        } catch (Exception $e) {
            self::save_log(
                'Product',
                $this->_name,
                'Error Creating DNS Configuration Ticket',
                ['domain' => $domain, 'client_id' => $client_id],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }

    /**
     * Get localized DNS configuration message
     * 
     * @param string $lang Language code
     * @param string $domain Domain name
     * @param array $required_records Required DNS records
     * @return string Localized message content
     */
    private function get_dns_configuration_message($lang, $domain, $required_records)
    {
        // Basic English template for all messages
        $message = "# DNS Configuration Instructions for {$domain}\n\n";
        $message .= "⚠️ **Important Notice:** Your domain **{$domain}** is not correctly configured for Blackwall protection.\n\n";
        $message .= "For Blackwall to protect your website, you need to point your domain to our protection servers using the DNS settings below:\n\n";
        
        // A Records section
        $message .= "## A Records\n\n";
        $message .= "| Record Type | Name | Value |\n";
        $message .= "|------------|------|-------|\n";
        foreach ($required_records['A'] as $ip) {
            $message .= "| A | @ | {$ip} |\n";
        }
        
        // AAAA Records section
        $message .= "\n## AAAA Records (IPv6)\n\n";
        $message .= "| Record Type | Name | Value |\n";
        $message .= "|------------|------|-------|\n";
        foreach ($required_records['AAAA'] as $ipv6) {
            $message .= "| AAAA | @ | {$ipv6} |\n";
        }
        
        // Instructions for www subdomain
        $message .= "\n## www Subdomain\n\n";
        $message .= "If you want to use www.{$domain}, you should also add the same records for the www subdomain or create a CNAME record:\n\n";
        $message .= "| Record Type | Name | Value |\n";
        $message .= "|------------|------|-------|\n";
        $message .= "| CNAME | www | {$domain} |\n";
        
        // DNS propagation note
        $message .= "\n## DNS Propagation\n\n";
        $message .= "After updating your DNS settings, it may take up to 24-48 hours for the changes to propagate globally. During this time, you may experience intermittent connectivity to your website.\n\n";
        
        // Support note
        $message .= "## Need Help?\n\n";
        $message .= "If you need assistance with these settings, please reply to this ticket. Our team will be happy to guide you through the process.\n\n";
        $message .= "You can also check your current DNS configuration using online tools like [MXToolbox](https://mxtoolbox.com/DNSLookup.aspx) or [DNSChecker](https://dnschecker.org/).\n\n";
        
        // Localize the message based on language if needed
        switch ($lang) {
            case 'de':
                // German translation would go here
                break;
            case 'fr':
                // French translation would go here
                break;
            case 'es':
                // Spanish translation would go here
                break;
            case 'nl':
                // Dutch translation would go here
                break;
        }
        
        return $message;
    }
    /**
     * Create new Blackwall service
     */
    public function create($order_options=[])
    {
        try {
            // First try to get domain from order options
            $user_domain = isset($this->order["options"]["domain"]) 
                ? $this->order["options"]["domain"] 
                : false;
            
            // If not found, try getting from requirements
            if(!$user_domain && isset($this->val_of_requirements["user_domain"])) {
                $user_domain = $this->val_of_requirements["user_domain"];
            }
            
            // Get user information from WISECP user data
            $user_email = $this->user["email"];
            $first_name = $this->user["name"];
            $last_name = $this->user["surname"];

            // Validate inputs
            if(!$user_domain) {
                $this->error = $this->lang["error_missing_domain"];
                return false;
            }
            // Log the values for debugging
            self::save_log(
                'Product',
                $this->_name,
                'create_values',
                [
                    'domain' => $user_domain,
                    'email' => $user_email,
                    'name' => $first_name,
                    'surname' => $last_name,
                    'order_options' => $order_options,
                    'order' => $this->order,
                    'requirements' => $this->val_of_requirements
                ],
                'Values being used for service creation',
                null
            );

            try {
                // Step 1: Create a subaccount in Botguard
                $subaccount_data = [
                    'email' => $user_email,
                    'first_name' => $first_name,
                    'last_name' => $last_name
                ];
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Creating subaccount',
                    $subaccount_data,
                    null,
                    null
                );
                
                $subaccount_result = $this->api_request('/user', 'POST', $subaccount_data);
                
                // Extract the user ID and API key from the response
                $user_id = isset($subaccount_result['id']) ? $subaccount_result['id'] : null;
                $user_api_key = isset($subaccount_result['api_key']) ? $subaccount_result['api_key'] : null;
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Subaccount created',
                    [
                        'user_id' => $user_id,
                        'api_key_first_chars' => $user_api_key ? substr($user_api_key, 0, 5) . '...' : 'null'
                    ],
                    null,
                    null
                );
                
                if (!$user_id) {
                    throw new Exception("Failed to get user ID from Botguard API response");
                }
                
                // Step 2: Also create user in GateKeeper
                try {
                    $gatekeeper_user_data = [
                        'id' => $user_id,
                        'tag' => 'wisecp'
                    ];
                    
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Creating user in GateKeeper',
                        $gatekeeper_user_data,
                        null,
                        null
                    );
                    
                    $gatekeeper_user_result = $this->gatekeeper_api_request('/user', 'POST', $gatekeeper_user_data);
                    
                    self::save_log(
                        'Product',
                        $this->_name,
                        'User created in GateKeeper',
                        $gatekeeper_user_result,
                        null,
                        null
                    );
                } catch (Exception $gk_user_e) {
                    // Log error but continue - the user might already exist in GateKeeper
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Error creating user in GateKeeper',
                        ['error' => $gk_user_e->getMessage()],
                        $gk_user_e->getMessage(),
                        $gk_user_e->getTraceAsString()
                    );
                    // Continue execution - don't break the process for this
                }
                // Step 3: Add the domain to the subaccount in Botguard
                $website_data = [
                    'domain' => $user_domain,
                    'user' => $user_id
                ];
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Creating domain in Botguard',
                    $website_data,
                    null,
                    null
                );
                
                $website_result = $this->api_request('/website', 'POST', $website_data);
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Domain created in Botguard',
                    $website_result,
                    null,
                    null
                );
                
                // Step 4: Also add the domain in GateKeeper - UPDATED WITH DNS LOOKUP
                try {
                    // Get the A records for the domain
                    $domain_ips = $this->get_domain_a_records($user_domain);
                    // Get AAAA records if available
                    $domain_ipv6s = $this->get_domain_aaaa_records($user_domain);
                    
                    $gatekeeper_website_data = [
                        'domain' => $user_domain,
                        'subdomain' => ['www'],
                        'ip' => $domain_ips, // Use the dynamically looked up IPs
                        'ipv6' => $domain_ipv6s, // Use the dynamically looked up IPv6 addresses
                        'user_id' => $user_id,
                        'tag' => ['wisecp'],
                        'status' => 'setup',
                        'settings' => [
                            'rulesets' => [
                                'wordpress' => false,
                                'joomla' => false,
                                'drupal' => false,
                                'cpanel' => false,
                                'bitrix' => false,
                                'dokuwiki' => false,
                                'xenforo' => false,
                                'nextcloud' => false,
                                'prestashop' => false
                            ],
                            'rules' => [
                                'search_engines' => 'grant',
                                'social_networks' => 'grant',
                                'services_and_payments' => 'grant',
                                'humans' => 'grant',
                                'security_issues' => 'deny',
                                'content_scrapers' => 'deny',
                                'emulated_humans' => 'captcha',
                                'suspicious_behaviour' => 'captcha'
                            ],
                            'loadbalancer' => [
                                'upstreams_use_https' => false,
                                'enable_http3' => true,
                                'force_https' => true,
                                'cache_static_files' => true,
                                'cache_dynamic_pages' => false,
                                'ddos_protection' => false,
                                'ddos_protection_advanced' => false,
                                'botguard_protection' => true,
                                'certs_issuer' => 'letsencrypt',
                                'force_subdomains_redirect' => false
                            ]
                        ]
                    ];
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Creating domain in GateKeeper',
                        $gatekeeper_website_data,
                        null,
                        null
                    );
                    
                    $gatekeeper_website_result = $this->gatekeeper_api_request('/website', 'POST', $gatekeeper_website_data);
                    
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Domain created in GateKeeper',
                        $gatekeeper_website_result,
                        null,
                        null
                    );
                } catch (Exception $gk_website_e) {
                    // Log error but continue - the domain might already exist in GateKeeper
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Error creating domain in GateKeeper',
                        ['domain' => $user_domain, 'error' => $gk_website_e->getMessage()],
                        $gk_website_e->getMessage(),
                        $gk_website_e->getTraceAsString()
                    );
                    // Continue execution - don't break the process for this
                }
                
                // Step 5: Add a delay before updating the domain status
                sleep(2);
                
                // Step 6: Activate the domain by setting status to online in Botguard
                $update_data = [
                    'status' => 'online'
                ];
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Updating domain status to online in Botguard',
                    ['domain' => $user_domain, 'data' => $update_data],
                    null,
                    null
                );
                
                try {
                    $update_result = $this->api_request('/website/' . $user_domain, 'PUT', $update_data);
                    
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Domain status updated in Botguard',
                        $update_result,
                        null,
                        null
                    );
                } catch (Exception $update_e) {
                    // Log the error but continue
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Error updating domain status in Botguard',
                        ['domain' => $user_domain, 'error' => $update_e->getMessage()],
                        $update_e->getMessage(),
                        $update_e->getTraceAsString()
                    );
                }
                // Step 7: Also update the domain status in GateKeeper - UPDATED WITH DNS LOOKUP
                try {
                    // Get the A records for the domain (refreshed)
                    $domain_ips = $this->get_domain_a_records($user_domain);
                    // Get AAAA records if available (refreshed)
                    $domain_ipv6s = $this->get_domain_aaaa_records($user_domain);
                    
                    $gatekeeper_update_data = [
                        'domain' => $user_domain,
                        'user_id' => $user_id,
                        'subdomain' => ['www'],
                        'ip' => $domain_ips, // Use the dynamically looked up IPs
                        'ipv6' => $domain_ipv6s, // Use the dynamically looked up IPv6 addresses
                        'status' => 'online',
                        'settings' => [
                            'rulesets' => [
                                'wordpress' => false,
                                'joomla' => false,
                                'drupal' => false,
                                'cpanel' => false,
                                'bitrix' => false,
                                'dokuwiki' => false,
                                'xenforo' => false,
                                'nextcloud' => false,
                                'prestashop' => false
                            ],
                            'rules' => [
                                'search_engines' => 'grant',
                                'social_networks' => 'grant',
                                'services_and_payments' => 'grant',
                                'humans' => 'grant',
                                'security_issues' => 'deny',
                                'content_scrapers' => 'deny',
                                'emulated_humans' => 'captcha',
                                'suspicious_behaviour' => 'captcha'
                            ],
                            'loadbalancer' => [
                                'upstreams_use_https' => true,
                                'enable_http3' => true,
                                'force_https' => true,
                                'cache_static_files' => true,
                                'cache_dynamic_pages' => false,
                                'ddos_protection' => false,
                                'ddos_protection_advanced' => false,
                                'botguard_protection' => true,
                                'certs_issuer' => 'letsencrypt',
                                'force_subdomains_redirect' => false
                            ]
                        ]
                    ];
                    
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Updating domain status to online in GateKeeper',
                        ['domain' => $user_domain, 'data' => $gatekeeper_update_data],
                        null,
                        null
                    );
                    
                    $gatekeeper_update_result = $this->gatekeeper_api_request('/website/' . $user_domain, 'PUT', $gatekeeper_update_data);
                    
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Domain status updated in GateKeeper',
                        $gatekeeper_update_result,
                        null,
                        null
                    );
                    
                    // Step 8: Register hook for DNS verification after creation
                    $this->register_dns_check_hook($user_domain, $this->order["id"]);
                    
                } catch (Exception $gk_update_e) {
                    // Log the error but continue
                    self::save_log(
                        'Product',
                        $this->_name,
                        'Error updating domain status in GateKeeper',
                        ['domain' => $user_domain, 'error' => $gk_update_e->getMessage()],
                        $gk_update_e->getMessage(),
                        $gk_update_e->getTraceAsString()
                    );
                }
                
                // Return the successful data to store in the service
                return [
                    'config' => [
                        'blackwall_domain' => $user_domain,
                        'blackwall_user_id' => $user_id,
                        'blackwall_api_key' => $user_api_key,
                    ],
                    'creation_info' => []
                ];
            } catch (Exception $api_e) {
                // If there's an API-specific error, log it
                self::save_log(
                    'Product',
                    $this->_name,
                    'API Error',
                    [
                        'domain' => $user_domain,
                        'email' => $user_email
                    ],
                    $api_e->getMessage(),
                    $api_e->getTraceAsString()
                );
                
                $this->error = $api_e->getMessage();
                return false;
            }
        }
        catch (Exception $e) {
            $this->error = $e->getMessage();
            self::save_log(
                'Product',
                $this->_name,
                __FUNCTION__,
                [
                    'order' => $this->order, 
                    'requirements' => $this->val_of_requirements,
                    'user' => [
                        'email' => isset($this->user["email"]) ? $this->user["email"] : null,
                        'name' => isset($this->user["name"]) ? $this->user["name"] : null,
                        'surname' => isset($this->user["surname"]) ? $this->user["surname"] : null
                    ]
                ],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }
    /**
     * Renewal of service
     */
    public function renewal($order_options=[])
    {
        try {
            // For renewal, we just need to verify the domain is still active
            $domain = isset($this->options["config"]["blackwall_domain"]) 
                ? $this->options["config"]["blackwall_domain"] 
                : false;
            
            $user_id = isset($this->options["config"]["blackwall_user_id"]) 
                ? $this->options["config"]["blackwall_user_id"] 
                : false;

            if(!$domain) {
                $this->error = $this->lang["error_missing_domain"];
                return false;
            }
            // Call the Botguard API to verify the domain exists
            $result = $this->api_request('/website/' . $domain, 'GET');
            
            // Check if domain is paused and reactivate if needed
            if(isset($result['status']) && $result['status'] === 'paused') {
                $update_data = [
                    'status' => 'online'
                ];
                
                // Update in Botguard
                $result = $this->api_request('/website/' . $domain, 'PUT', $update_data);
                
                // Also update in GateKeeper - UPDATED WITH DNS LOOKUP
                try {
                    // Get the A records for the domain
                    $domain_ips = $this->get_domain_a_records($domain);
                    // Get AAAA records if available
                    $domain_ipv6s = $this->get_domain_aaaa_records($domain);
                    
                    $gatekeeper_update_data = [
                        'domain' => $domain,
                        'subdomain' => ['www'],
                        'ip' => $domain_ips, // Use the dynamically looked up IPs
                        'ipv6' => $domain_ipv6s, // Use the dynamically looked up IPv6 addresses
                        'user_id' => $user_id,
                        'status' => 'online',
                        'settings' => [
                            'rulesets' => [
                                'wordpress' => false,
                                'joomla' => false,
                                'drupal' => false,
                                'cpanel' => false,
                                'bitrix' => false,
                                'dokuwiki' => false,
                                'xenforo' => false,
                                'nextcloud' => false,
                                'prestashop' => false
                            ],
                            'rules' => [
                                'search_engines' => 'grant',
                                'social_networks' => 'grant',
                                'services_and_payments' => 'grant',
                                'humans' => 'grant',
                                'security_issues' => 'deny',
                                'content_scrapers' => 'deny',
                                'emulated_humans' => 'captcha',
                                'suspicious_behaviour' => 'captcha'
                            ],
                            'loadbalancer' => [
                                'upstreams_use_https' => true,
                                'enable_http3' => true,
                                'force_https' => true,
                                'cache_static_files' => true,
                                'cache_dynamic_pages' => false,
                                'ddos_protection' => false,
                                'ddos_protection_advanced' => false,
                                'botguard_protection' => true,
                                'certs_issuer' => 'letsencrypt',
                                'force_subdomains_redirect' => false
                            ]
                        ]
                    ];
                    
                    $this->gatekeeper_api_request('/website/' . $domain, 'PUT', $gatekeeper_update_data);
                    
                    // Register hook for DNS verification after renewal
                    $this->register_dns_check_hook($domain, $this->order["id"]);
                } catch (Exception $gk_e) {
                    // Log but continue
                    self::save_log(
                        'Product',
                        $this->_name,
                        'GateKeeper update error during renewal',
                        ['domain' => $domain, 'error' => $gk_e->getMessage()],
                        $gk_e->getMessage(),
                        $gk_e->getTraceAsString()
                    );
                }
            }
            
            return true;
        }
        catch (Exception $e) {
            $this->error = $e->getMessage();
            self::save_log(
                'Product',
                $this->_name,
                __FUNCTION__,
                ['order' => $this->order],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }
    /**
     * Suspend service
     */
    public function suspend()
    {
        try {
            $domain = isset($this->options["config"]["blackwall_domain"]) 
                ? $this->options["config"]["blackwall_domain"] 
                : false;
            
            $user_id = isset($this->options["config"]["blackwall_user_id"]) 
                ? $this->options["config"]["blackwall_user_id"] 
                : false;

            if(!$domain) {
                $this->error = $this->lang["error_missing_domain"];
                return false;
            }

            // Step 1: Call the Botguard API to set domain status to 'paused'
            $update_data = [
                'status' => 'paused'
            ];
            
            self::save_log(
                'Product',
                $this->_name,
                'Setting domain status to paused in Botguard',
                ['domain' => $domain, 'data' => $update_data],
                null,
                null
            );
            
            $result = $this->api_request('/website/' . $domain, 'PUT', $update_data);
            
            self::save_log(
                'Product',
                $this->_name,
                'Domain status set to paused in Botguard',
                $result,
                null,
                null
            );
            
            // Step 2: Also update the domain status in GateKeeper - UPDATED WITH DNS LOOKUP
            try {
                // Get the A records for the domain
                $domain_ips = $this->get_domain_a_records($domain);
                // Get AAAA records if available
                $domain_ipv6s = $this->get_domain_aaaa_records($domain);
                
                $gatekeeper_update_data = [
                    'domain' => $domain,
                    'user_id' => $user_id,
                    'subdomain' => ['www'],
                    'ip' => $domain_ips, // Use the dynamically looked up IPs
                    'ipv6' => $domain_ipv6s, // Use the dynamically looked up IPv6 addresses
                    'status' => 'paused',
                    'settings' => [
                        'rulesets' => [
                            'wordpress' => false,
                            'joomla' => false,
                            'drupal' => false,
                            'cpanel' => false,
                            'bitrix' => false,
                            'dokuwiki' => false,
                            'xenforo' => false,
                            'nextcloud' => false,
                            'prestashop' => false
                        ],
                        'rules' => [
                            'search_engines' => 'grant',
                            'social_networks' => 'grant',
                            'services_and_payments' => 'grant',
                            'humans' => 'grant',
                            'security_issues' => 'deny',
                            'content_scrapers' => 'deny',
                            'emulated_humans' => 'captcha',
                            'suspicious_behaviour' => 'captcha'
                        ],
                        'loadbalancer' => [
                            'upstreams_use_https' => true,
                            'enable_http3' => true,
                            'force_https' => true,
                            'cache_static_files' => true,
                            'cache_dynamic_pages' => false,
                            'ddos_protection' => false,
                            'ddos_protection_advanced' => false,
                            'botguard_protection' => true,
                            'certs_issuer' => 'letsencrypt',
                            'force_subdomains_redirect' => false
                        ]
                    ]
                ];
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Setting domain status to paused in GateKeeper',
                    ['domain' => $domain, 'data' => $gatekeeper_update_data],
                    null,
                    null
                );
                $gatekeeper_result = $this->gatekeeper_api_request('/website/' . $domain, 'PUT', $gatekeeper_update_data);
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Domain status set to paused in GateKeeper',
                    $gatekeeper_result,
                    null,
                    null
                );
            } catch (Exception $gk_e) {
                // Log error but continue - don't fail if GateKeeper update fails
                self::save_log(
                    'Product',
                    $this->_name,
                    'Error setting domain status in GateKeeper',
                    ['domain' => $domain, 'error' => $gk_e->getMessage()],
                    $gk_e->getMessage(),
                    $gk_e->getTraceAsString()
                );
            }
            
            return true;
        }
        catch (Exception $e) {
            $this->error = $e->getMessage();
            self::save_log(
                'Product',
                $this->_name,
                __FUNCTION__,
                ['order' => $this->order],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }

    /**
     * Unsuspend service
     */
    public function unsuspend()
    {
        try {
            $domain = isset($this->options["config"]["blackwall_domain"]) 
                ? $this->options["config"]["blackwall_domain"] 
                : false;
            
            $user_id = isset($this->options["config"]["blackwall_user_id"]) 
                ? $this->options["config"]["blackwall_user_id"] 
                : false;

            if(!$domain) {
                $this->error = $this->lang["error_missing_domain"];
                return false;
            }

            // Step 1: Call the Botguard API to set domain status to 'online'
            $update_data = [
                'status' => 'online'
            ];
            
            self::save_log(
                'Product',
                $this->_name,
                'Setting domain status to online in Botguard',
                ['domain' => $domain, 'data' => $update_data],
                null,
                null
            );
            
            $result = $this->api_request('/website/' . $domain, 'PUT', $update_data);
            
            self::save_log(
                'Product',
                $this->_name,
                'Domain status set to online in Botguard',
                $result,
                null,
                null
            );
            
            // Step 2: Also update the domain status in GateKeeper - UPDATED WITH DNS LOOKUP
            try {
                // Get the A records for the domain
                $domain_ips = $this->get_domain_a_records($domain);
                // Get AAAA records if available
                $domain_ipv6s = $this->get_domain_aaaa_records($domain);
                
                $gatekeeper_update_data = [
                    'domain' => $domain,
                    'subdomain' => ['www'],
                    'ip' => $domain_ips, // Use the dynamically looked up IPs
                    'ipv6' => $domain_ipv6s, // Use the dynamically looked up IPv6 addresses
                    'user_id' => $user_id,
                    'status' => 'online',
                    'settings' => [
                        'rulesets' => [
                            'wordpress' => false,
                            'joomla' => false,
                            'drupal' => false,
                            'cpanel' => false,
                            'bitrix' => false,
                            'dokuwiki' => false,
                            'xenforo' => false,
                            'nextcloud' => false,
                            'prestashop' => false
                        ],
                        'rules' => [
                            'search_engines' => 'grant',
                            'social_networks' => 'grant',
                            'services_and_payments' => 'grant',
                            'humans' => 'grant',
                            'security_issues' => 'deny',
                            'content_scrapers' => 'deny',
                            'emulated_humans' => 'captcha',
                            'suspicious_behaviour' => 'captcha'
                        ],
                        'loadbalancer' => [
                            'upstreams_use_https' => true,
                            'enable_http3' => true,
                            'force_https' => true,
                            'cache_static_files' => true,
                            'cache_dynamic_pages' => false,
                            'ddos_protection' => false,
                            'ddos_protection_advanced' => false,
                            'botguard_protection' => true,
                            'certs_issuer' => 'letsencrypt',
                            'force_subdomains_redirect' => false
                        ]
                    ]
                ];
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Setting domain status to online in GateKeeper',
                    ['domain' => $domain, 'data' => $gatekeeper_update_data],
                    null,
                    null
                );
                $gatekeeper_result = $this->gatekeeper_api_request('/website/' . $domain, 'PUT', $gatekeeper_update_data);
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Domain status set to online in GateKeeper',
                    $gatekeeper_result,
                    null,
                    null
                );
                
                // Register hook for DNS verification after unsuspension
                $this->register_dns_check_hook($domain, $this->order["id"]);
            } catch (Exception $gk_e) {
                // Log error but continue - don't fail if GateKeeper update fails
                self::save_log(
                    'Product',
                    $this->_name,
                    'Error setting domain status in GateKeeper',
                    ['domain' => $domain, 'error' => $gk_e->getMessage()],
                    $gk_e->getMessage(),
                    $gk_e->getTraceAsString()
                );
            }
            
            return true;
        }
        catch (Exception $e) {
            $this->error = $e->getMessage();
            self::save_log(
                'Product',
                $this->_name,
                __FUNCTION__,
                ['order' => $this->order],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }
    /**
     * Delete service
     */
    public function delete()
    {
        try {
            $domain = isset($this->options["config"]["blackwall_domain"]) 
                ? $this->options["config"]["blackwall_domain"] 
                : false;
            
            $user_id = isset($this->options["config"]["blackwall_user_id"]) 
                ? $this->options["config"]["blackwall_user_id"] 
                : false;

            if(!$domain) {
                $this->error = $this->lang["error_missing_domain"];
                return false;
            }

            // Step 1: Delete the domain from Botguard
            self::save_log(
                'Product',
                $this->_name,
                'Deleting domain from Botguard',
                ['domain' => $domain],
                null,
                null
            );
            
            $result = $this->api_request('/website/' . $domain, 'DELETE');
            
            self::save_log(
                'Product',
                $this->_name,
                'Domain deleted from Botguard',
                $result,
                null,
                null
            );
            
            // Step 2: Also delete the domain from GateKeeper
            try {
                self::save_log(
                    'Product',
                    $this->_name,
                    'Deleting domain from GateKeeper',
                    ['domain' => $domain],
                    null,
                    null
                );
                $gatekeeper_result = $this->gatekeeper_api_request('/website/' . $domain, 'DELETE');
                
                self::save_log(
                    'Product',
                    $this->_name,
                    'Domain deleted from GateKeeper',
                    $gatekeeper_result,
                    null,
                    null
                );
            } catch (Exception $gk_e) {
                // Log error but continue - don't fail if GateKeeper deletion fails
                self::save_log(
                    'Product',
                    $this->_name,
                    'Error deleting domain from GateKeeper',
                    ['domain' => $domain, 'error' => $gk_e->getMessage()],
                    $gk_e->getMessage(),
                    $gk_e->getTraceAsString()
                );
            }
            
            // Step 3: Consider deleting the user if this was their only domain
            // In a real implementation, you would check if the user has any other domains first
            // This is just a placeholder for that logic
            
            return true;
        }
        catch (Exception $e) {
            $this->error = $e->getMessage();
            self::save_log(
                'Product',
                $this->_name,
                __FUNCTION__,
                ['order' => $this->order],
                $e->getMessage(),
                $e->getTraceAsString()
            );
            return false;
        }
    }
    /**
     * Client Area Display
     */
    public function clientArea()
    {
        $content = $this->clientArea_buttons_output();
        $_page   = $this->page;

        if(!$_page) $_page = 'home';

        $domain = isset($this->options["config"]["blackwall_domain"]) 
            ? $this->options["config"]["blackwall_domain"] 
            : false;
        
        // Use master API key from module settings
        $api_key = $this->config["settings"]["api_key"];
        
        $variables = [
            'domain' => $domain,
            'api_key' => $api_key,
            'lang' => $this->lang,
        ];

        $content .= $this->get_page('clientArea-'.$_page, $variables);
        return $content;
    }

    /**
     * Client Area Buttons
     */
    public function clientArea_buttons()
    {
        $buttons = [];
        
        if($this->page && $this->page != "home")
        {
            $buttons['home'] = [
                'text' => $this->lang["turn_back"],
                'type' => 'page-loader',
            ];
        }
        return $buttons;
    }

    /**
     * Admin Area Service Fields
     */
    public function adminArea_service_fields(){
        $config = $this->options["config"];
        
        $user_domain = isset($config["blackwall_domain"]) ? $config["blackwall_domain"] : NULL;
        
        return [
            'blackwall_domain' => [
                'wrap_width' => 100,
                'name' => $this->lang["domain_name"],
                'description' => $this->lang["domain_description"],
                'type' => "text",
                'value' => $user_domain,
            ],
        ];
    }

    /**
     * Save Admin Area Service Fields
     */
    public function save_adminArea_service_fields($data=[]){
        /* OLD DATA */
        $o_config = $data['old']['config'];
        
        /* NEW DATA */
        $n_config = $data['new']['config'];
        
        // Validate domain
        if(!isset($n_config['blackwall_domain']) || $n_config['blackwall_domain'] == '') {
            $this->error = $this->lang["error_missing_domain"];
            return false;
        }
        
        // Check if domain needs updating
        if($o_config['blackwall_domain'] != $n_config['blackwall_domain']) {
            // This would be complex to implement since it requires recreating
            // the domain in Blackwall. For simplicity, we'll disallow this.
            $this->error = $this->lang["error_cannot_change_domain"];
            return false;
        }
        
        return [
            'config' => $n_config,
        ];
    }

    /**
     * Admin Area Buttons
     */
    public function adminArea_buttons()
    {
        $buttons = [];
        $domain = isset($this->options["config"]["blackwall_domain"]) 
            ? $this->options["config"]["blackwall_domain"] 
            : false;
        
        if($domain) {
            $buttons['view_in_blackwall'] = [
                'text'  => $this->lang["view_in_blackwall"],
                'type'  => 'link',
                'url'   => 'https://apiv2.botguard.net/en/website/'.$domain.'/statistics?api-key='.$this->config["settings"]["api_key"],
                'target_blank' => true,
            ];
            
            $buttons['check_status'] = [
                'text'  => $this->lang["check_status"],
                'type'  => 'transaction',
            ];
            
            $buttons['check_dns'] = [
                'text'  => $this->lang["check_dns"],
                'type'  => 'transaction',
            ];
        }

        return $buttons;
    }

    /**
     * Admin Area Check Status
     */
    public function use_adminArea_check_status()
    {
        $domain = isset($this->options["config"]["blackwall_domain"]) 
            ? $this->options["config"]["blackwall_domain"] 
            : false;

        if(!$domain) {
            echo Utility::jencode([
                'status' => "error",
                'message' => $this->lang["error_missing_domain"],
            ]);
            return false;
        }

        try {
            // Call the Botguard API to get the domain status
            $result = $this->api_request('/website/' . $domain, 'GET');
            
            $status = isset($result['status']) ? $result['status'] : 'unknown';
            
            echo Utility::jencode([
                'status' => "successful",
                'message' => $this->lang["domain_status"] . ": " . $status,
            ]);
            return true;
        } catch (Exception $e) {
            echo Utility::jencode([
                'status' => "error",
                'message' => $e->getMessage(),
            ]);
            return false;
        }
    }
    
    /**
     * Admin Area Check DNS Configuration
     */
    public function use_adminArea_check_dns()
    {
        $domain = isset($this->options["config"]["blackwall_domain"]) 
            ? $this->options["config"]["blackwall_domain"] 
            : false;

        if(!$domain) {
            echo Utility::jencode([
                'status' => "error",
                'message' => $this->lang["error_missing_domain"],
            ]);
            return false;
        }

        try {
            // Check if the domain's DNS is properly configured
            $is_configured = $this->check_domain_dns_configuration($domain);
            
            if ($is_configured) {
                echo Utility::jencode([
                    'status' => "successful",
                    'message' => $this->lang["dns_configured_correctly"],
                ]);
            } else {
                echo Utility::jencode([
                    'status' => "warning",
                    'message' => $this->lang["dns_not_configured_correctly"],
                ]);
            }
            return true;
        } catch (Exception $e) {
            echo Utility::jencode([
                'status' => "error",
                'message' => $e->getMessage(),
            ]);
            return false;
        }
    }
    /**
     * Helper to make API requests to Botguard
     * 
     * @param string $endpoint API endpoint to call
     * @param string $method HTTP method to use
     * @param array $data Data to send with the request
     * @param string $override_api_key Optional API key to use instead of the module config
     * @return array Response data
     */
    private function api_request($endpoint, $method = 'GET', $data = [], $override_api_key = null)
    {
        // Get API key from module config or use override if provided
        $api_key = $override_api_key ?: $this->config["settings"]["api_key"];
        
        if (empty($api_key)) {
            throw new Exception("API key is required for Botguard API requests.");
        }
        
        // Build full API URL
        $url = 'https://apiv2.botguard.net' . $endpoint;
        
        // Log the API request
        self::save_log(
            'Product',
            $this->_name,
            'API Request: ' . $method . ' ' . $url,
            [
                'data' => $data,
                'api_key_first_chars' => substr($api_key, 0, 5) . '...'
            ],
            null,
            null
        );
        
        // Initialize cURL
        $ch = curl_init();
        
        // Setup common cURL options
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        
        // Set headers including Authorization
        $headers = [
            'Authorization: Bearer ' . $api_key,
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ];
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        // Set up the request based on HTTP method
        switch ($method) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                if (!empty($data)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
                }
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                if (!empty($data)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
                }
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
            default: // GET
                if (!empty($data)) {
                    $url .= '?' . http_build_query($data);
                    curl_setopt($ch, CURLOPT_URL, $url);
                }
                break;
        }

        // Execute the request
        $response = curl_exec($ch);
        $err = curl_error($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);
        
        // Log the response
        self::save_log(
            'Product',
            $this->_name,
            'API Response: ' . $method . ' ' . $url,
            [
                'status_code' => $info['http_code'],
                'response' => $response,
                'error' => $err
            ],
            null,
            null
        );
        
        // Handle errors
        if ($err) {
            throw new Exception('cURL Error: ' . $err);
        }
        
        // Parse response
        $response_data = json_decode($response, true);
        
        // Handle error responses
        if (isset($response_data['status']) && $response_data['status'] === 'error') {
            throw new Exception('API Error: ' . $response_data['message']);
        }
        
        // Handle specific HTTP status codes
        if ($info['http_code'] >= 400) {
            throw new Exception('HTTP Error: ' . $info['http_code'] . ' - ' . $response);
        }
        
        return $response_data;
    }

    /**
     * Helper to make API requests to GateKeeper
     * 
     * @param string $endpoint API endpoint to call
     * @param string $method HTTP method to use
     * @param array $data Data to send with the request
     * @param string $override_api_key Optional API key to use instead of the module config
     * @return array Response data
     */
    private function gatekeeper_api_request($endpoint, $method = 'GET', $data = [], $override_api_key = null)
    {
        // Get API key from module config or use override if provided
        $api_key = $override_api_key ?: $this->config["settings"]["api_key"];
        
        if (empty($api_key)) {
            throw new Exception("API key is required for GateKeeper API requests.");
        }
        
        // Get the primary server from config and build the GateKeeper API URL
        $primary_server = $this->config["settings"]["primary_server"];
        if (empty($primary_server)) {
            throw new Exception("Primary server is required for GateKeeper API requests.");
        }

        // Build full API URL
        $url = 'https://api.blackwall.klikonline.nl:8443/v1.0' . $endpoint;
        
        // Log the API request
        self::save_log(
            'Product',
            $this->_name,
            'GateKeeper API Request: ' . $method . ' ' . $url,
            [
                'data' => $data,
                'api_key_first_chars' => substr($api_key, 0, 5) . '...'
            ],
            null,
            null
        );
        
        // Initialize cURL
        $ch = curl_init();
        
        // Setup common cURL options
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        // Disable SSL verification for development/testing
        // In production, you should enable proper SSL verification
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        
        // Set headers including Authorization
        $headers = [
            'Authorization: Bearer ' . $api_key,
            'Content-Type: application/json',
            'Accept: application/json'
        ];
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        // Set up the request based on HTTP method
        switch ($method) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                if (!empty($data)) {
                    $json_data = json_encode($data);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
                }
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                if (!empty($data)) {
                    $json_data = json_encode($data);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
                }
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
            default: // GET
                if (!empty($data)) {
                    $url .= '?' . http_build_query($data);
                    curl_setopt($ch, CURLOPT_URL, $url);
                }
                break;
        }
        // Execute the request
        $response = curl_exec($ch);
        $err = curl_error($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);
        
        // Log the response
        self::save_log(
            'Product',
            $this->_name,
            'GateKeeper API Response: ' . $method . ' ' . $url,
            [
                'status_code' => $info['http_code'],
                'response' => $response,
                'error' => $err
            ],
            null,
            null
        );
        
        // Handle errors
        if ($err) {
            throw new Exception('cURL Error: ' . $err);
        }
        
        // Parse response if it's JSON
        if (!empty($response)) {
            $response_data = json_decode($response, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                // If it's a valid JSON response
                if (isset($response_data['status']) && $response_data['status'] === 'error') {
                    throw new Exception('GateKeeper API Error: ' . $response_data['message']);
                }
                return $response_data;
            }
        }
        
        // If we got here, return the raw response for non-JSON responses
        // or return an empty array for empty responses (like 204 No Content)
        return !empty($response) ? ['raw_response' => $response] : [];
    }
}
// Register the DNS check hook at module load time
Hook::add("OrderActivated", 1, function($params = []) {
    // Check if this is Blackwall product (ID 105)
    if (isset($params['product_id']) && $params['product_id'] == 105) {
        $log_paths = [
            '/tmp/blackwall_dns_hook.log',
            __DIR__ . '/blackwall_dns_hook.log'
        ];
        
        // Log function
        $debug_log = function($message, $data = null) use ($log_paths) {
            $timestamp = date('Y-m-d H:i:s');
            $log_message = "[{$timestamp}] {$message}\n";
            
            if ($data !== null) {
                if (is_array($data) || is_object($data)) {
                    $log_message .= print_r($data, true) . "\n";
                } else {
                    $log_message .= $data . "\n";
                }
            }
            
            // Try to write to both locations
            foreach ($log_paths as $log_path) {
                try {
                    file_put_contents($log_path, $log_message, FILE_APPEND);
                } catch (Exception $e) {
                    // Silently fail if we can't write to this location
                }
            }
        };
        
        $debug_log("Blackwall DNS Hook triggered for order ID: " . $params['id']);
        
        // Get the domain name from order options
        $domain = isset($params['options']) && isset($params['options']['domain']) 
            ? $params['options']['domain'] 
            : '';
            
        if (empty($domain) && isset($params['options']) && isset($params['options']['config']) && 
            isset($params['options']['config']['blackwall_domain'])) {
            $domain = $params['options']['config']['blackwall_domain'];
        }
        
        $debug_log("Domain: {$domain}");
            
        if (!empty($domain)) {
            // Define the required DNS records for Blackwall protection
            $required_records = [
                'A' => ['49.13.161.213', '116.203.242.28'],
                'AAAA' => ['2a01:4f8:c2c:5a72::1', '2a01:4f8:1c1b:7008::1']
            ];
            
            // Function to check DNS configuration
            $check_dns_configuration = function($domain, $required_records) use ($debug_log) {
                $debug_log("Starting DNS check for domain: {$domain}");
                
                try {
                    // Get current DNS records for the domain
                    $a_records = @dns_get_record($domain, DNS_A);
                    $debug_log("A records found:", $a_records);
                    
                    $aaaa_records = @dns_get_record($domain, DNS_AAAA);
                    $debug_log("AAAA records found:", $aaaa_records);
                    
                    // Check if any of the required A records match
                    $has_valid_a_record = false;
                    foreach ($a_records as $record) {
                        if (in_array($record['ip'], $required_records['A'])) {
                            $has_valid_a_record = true;
                            $debug_log("Found valid A record: {$record['ip']}");
                            break;
                        }
                    }
                    
                    // Check if any of the required AAAA records match
                    $has_valid_aaaa_record = false;
                    foreach ($aaaa_records as $record) {
                        if (in_array($record['ipv6'], $required_records['AAAA'])) {
                            $has_valid_aaaa_record = true;
                            $debug_log("Found valid AAAA record: {$record['ipv6']}");
                            break;
                        }
                    }
                    
                    $result = $has_valid_a_record && $has_valid_aaaa_record;
                    $debug_log("DNS check result: " . ($result ? 'Correctly configured' : 'Not correctly configured'));
                    return $result;
                } catch (Exception $e) {
                    $debug_log("Exception in DNS check: " . $e->getMessage());
                    return false; // Default to false on error
                }
            };
            
            // Check if DNS is correctly configured
            $is_dns_configured = $check_dns_configuration($domain, $required_records);
            
            // Function to check if the time has expired
            $is_time_expired = function($order_id, $wait_time_hours) use ($debug_log) {
                $debug_log("Checking time expiration for order ID: {$order_id}, wait time: {$wait_time_hours} hours");
                
                // Check if there's a stored DNS check time
                $dns_check_file = sys_get_temp_dir() . '/blackwall_dns_check_' . md5($order_id) . '.json';
                if (file_exists($dns_check_file)) {
                    $dns_check_data = json_decode(file_get_contents($dns_check_file), true);
                    if (isset($dns_check_data['check_time'])) {
                        $activation_time = $dns_check_data['check_time'];
                        $debug_log("Found stored DNS check time: " . date('Y-m-d H:i:s', $activation_time));
                    } else {
                        // Fallback to current time minus 1 hour
                        $activation_time = time() - 3600;
                        $debug_log("No check time in data, using fallback time: " . date('Y-m-d H:i:s', $activation_time));
                    }
                } else {
                    // Fallback to current time minus 1 hour
                    $activation_time = time() - 3600;
                    $debug_log("No DNS check file, using fallback time: " . date('Y-m-d H:i:s', $activation_time));
                }
                
                $current_time = time();
                $wait_time_seconds = $wait_time_hours * 3600; // Convert hours to seconds
                
                $time_difference = $current_time - $activation_time;
                $hours_elapsed = round($time_difference / 3600, 2);
                
                $debug_log("Current time: " . date('Y-m-d H:i:s', $current_time));
                $debug_log("Time difference: {$time_difference} seconds ({$hours_elapsed} hours)");
                $debug_log("Required wait time: {$wait_time_seconds} seconds");
                
                $result = ($time_difference >= $wait_time_seconds);
                $debug_log("Wait time expired: " . ($result ? 'Yes' : 'No'));
                
                return $result;
            };
            
            // Wait for the specified time before sending ticket (6 hours by default)
            $wait_time = 6; // hours
            $time_expired = $is_time_expired($params['id'], $wait_time);
            
            // Function to create a ticket
            $create_ticket = function($params, $domain, $required_records) use ($debug_log) {
                $debug_log("Creating ticket for domain: {$domain}");
                
                try {
                    // Get client ID from order parameters
                    $client_id = $params['owner_id'] ?? 0;
                    
                    if (!$client_id) {
                        $debug_log("Client ID not found in params");
                        return;
                    }
                    
                    // Initialize Blackwall module instance to use its methods
                    $blackwall = new Blackwall();
                    
                    // Create the ticket using the module's method
                    $blackwall->create_dns_configuration_ticket($domain, $client_id, $params['id']);
                    
                    $debug_log("Ticket creation initiated");
                } catch (Exception $e) {
                    $debug_log("Exception occurred when creating ticket: " . $e->getMessage());
                    $debug_log("Exception trace: " . $e->getTraceAsString());
                }
            };
            
            // If DNS is not configured correctly and wait time has passed
            if (!$is_dns_configured && $time_expired) {
                $debug_log("DNS not configured correctly and wait time expired - creating ticket");
                $create_ticket($params, $domain, $required_records);
            } else {
                $debug_log("Not creating ticket - DNS configured: " . ($is_dns_configured ? 'Yes' : 'No') . 
                           ", Time expired: " . ($time_expired ? 'Yes' : 'No'));
            }
        } else {
            $debug_log("No domain found in order options");
        }
    }
});
