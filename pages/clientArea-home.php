<?php if(!defined("CORE_FOLDER")) return false; 

// Define the IP addresses for the GateKeeper nodes
$gatekeeper_nodes = [
    'bg-gk-01' => [
        'ipv4' => '49.13.161.213',
        'ipv6' => '2a01:4f8:c2c:5a72::1'
    ],
    'bg-gk-02' => [
        'ipv4' => '116.203.242.28',
        'ipv6' => '2a01:4f8:1c1b:7008::1'
    ]
];

// Function to check DNS records
function checkDNSRecords($domain, $gatekeeper_nodes) {
    $results = [
        'status' => false,
        'connected_to' => null,
        'ipv4_status' => false,
        'ipv6_status' => false,
        'ipv4_records' => [],
        'ipv6_records' => [],
        'missing_records' => []
    ];
    
    // Get the A records (IPv4)
    $a_records = @dns_get_record($domain, DNS_A);
    if ($a_records) {
        $results['ipv4_records'] = array_column($a_records, 'ip');
    }
    
    // Get the AAAA records (IPv6)
    $aaaa_records = @dns_get_record($domain, DNS_AAAA);
    if ($aaaa_records) {
        $results['ipv6_records'] = array_column($aaaa_records, 'ipv6');
    }
    
    // Check if the domain is connected to any of the GateKeeper nodes
    foreach ($gatekeeper_nodes as $node_name => $node_ips) {
        $ipv4_match = in_array($node_ips['ipv4'], $results['ipv4_records']);
        $ipv6_match = in_array($node_ips['ipv6'], $results['ipv6_records']);
        
        if ($ipv4_match || $ipv6_match) {
            $results['connected_to'] = $node_name;
            $results['ipv4_status'] = $ipv4_match;
            $results['ipv6_status'] = $ipv6_match;
            $results['status'] = true;
            
            // Check for missing records
            if (!$ipv4_match) {
                $results['missing_records'][] = [
                    'type' => 'A',
                    'value' => $node_ips['ipv4']
                ];
            }
            
            if (!$ipv6_match) {
                $results['missing_records'][] = [
                    'type' => 'AAAA',
                    'value' => $node_ips['ipv6']
                ];
            }
            
            break;
        }
    }
    
    // If not connected to any node, provide recommendations
    if (!$results['status']) {
        // Recommend the first node by default
        $recommended_node = 'bg-gk-01';
        $results['missing_records'] = [
            [
                'type' => 'A',
                'value' => $gatekeeper_nodes[$recommended_node]['ipv4']
            ],
            [
                'type' => 'AAAA',
                'value' => $gatekeeper_nodes[$recommended_node]['ipv6']
            ]
        ];
    }
    
    return $results;
}

// Check the DNS records for the domain
$dns_check = checkDNSRecords($domain, $gatekeeper_nodes);

?>

<div class="moderncardcon">
    <h4><?php echo $lang["service_info"]; ?></h4>
    
    <div class="singlecardinfo">
        <div class="cardbody">
            <div class="row">
                <div class="padding20">
                    <div class="formcon">
                        <div class="yuzde30"><?php echo $lang["protected_domain"]; ?></div>
                        <div class="yuzde70"><?php echo $domain; ?></div>
                    </div>
                    
                    <?php if(isset($service_status)): ?>
                    <div class="formcon">
                        <div class="yuzde30"><?php echo $lang["status"]; ?></div>
                        <div class="yuzde70"><?php echo $service_status; ?></div>
                    </div>
                    <?php endif; ?>
                    
                    <div class="formcon">
                        <div class="yuzde30">DNS Configuration Status</div>
                        <div class="yuzde70">
                            <?php if($dns_check['status']): ?>
                                <span style="color: green; font-weight: bold;">✓ Correctly configured</span>
                                <p>Your domain is connected to node <?php echo $dns_check['connected_to']; ?></p>
                                <?php if(!empty($dns_check['missing_records'])): ?>
                                    <div style="margin-top: 10px; color: orange;">
                                        <p><strong>Note:</strong> For optimal protection, please add these missing records:</p>
                                        <ul>
                                            <?php foreach($dns_check['missing_records'] as $record): ?>
                                                <li>Add <?php echo $record['type']; ?> record: <code><?php echo $record['value']; ?></code></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                            <?php else: ?>
                                <span style="color: red; font-weight: bold;">✕ Not properly configured</span>
                                <p>Your domain is not correctly pointed to the Blackwall protection servers. 
                                <a href="javascript:void(0);" onclick="openBlackwallTab('setup');" class="lbtn red">Click here for setup instructions</a></p>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="clear"></div><br>

<!-- Simple Tab System -->
<div id="blackwall-tab-system">
    <!-- Tab buttons -->
    <div class="blackwall-tab-buttons">
        <button class="blackwall-tab-button active" onclick="openBlackwallTab('statistics')"><i class="fa fa-bar-chart"></i> <?php echo $lang["view_statistics"]; ?></button>
        <button class="blackwall-tab-button" onclick="openBlackwallTab('events')"><i class="fa fa-list"></i> <?php echo $lang["view_events"]; ?></button>
        <button class="blackwall-tab-button" onclick="openBlackwallTab('settings')"><i class="fa fa-cog"></i> <?php echo $lang["edit_settings"]; ?></button>
        <button class="blackwall-tab-button" onclick="openBlackwallTab('setup')"><i class="fa fa-wrench"></i> <?php echo $lang["setup_instructions"]; ?></button>
    </div>

    <!-- Tab content -->
    <div id="blackwall-tab-statistics" class="blackwall-tab-content active">
        <div class="blackwall-iframe-header">
            <span>Statistics</span>
            <button onclick="refreshIframe('statistics-iframe')" class="refresh-btn"><i class="fa fa-refresh"></i> Refresh</button>
        </div>
        <iframe id="statistics-iframe" src="https://apiv2.botguard.net/en/website/<?php echo $domain; ?>/statistics?api-key=<?php echo $api_key; ?>" frameborder="0"></iframe>
    </div>

    <div id="blackwall-tab-events" class="blackwall-tab-content">
        <div class="blackwall-iframe-header">
            <span>Events Log</span>
            <button onclick="refreshIframe('events-iframe')" class="refresh-btn"><i class="fa fa-refresh"></i> Refresh</button>
        </div>
        <iframe id="events-iframe" src="https://apiv2.botguard.net/en/website/<?php echo $domain; ?>/events?api-key=<?php echo $api_key; ?>" frameborder="0"></iframe>
    </div>

    <div id="blackwall-tab-settings" class="blackwall-tab-content">
        <div class="blackwall-iframe-header">
            <span>Protection Settings</span>
            <button onclick="refreshIframe('settings-iframe')" class="refresh-btn"><i class="fa fa-refresh"></i> Refresh</button>
        </div>
        <iframe id="settings-iframe" src="https://apiv2.botguard.net/en/website/<?php echo $domain; ?>/edit?api-key=<?php echo $api_key; ?>" frameborder="0"></iframe>
    </div>

    <div id="blackwall-tab-setup" class="blackwall-tab-content">
        <div class="padding20">
            <h3>DNS Configuration Instructions</h3>
            
            <?php if($dns_check['status']): ?>
                <div class="green-info" style="background: #0c840c; color: white; border: 1px solid #096d09; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                    <p><strong>✓ Your domain is correctly configured!</strong></p>
                    <p>Your domain <strong><?php echo $domain; ?></strong> is properly connected to Blackwall protection via node <strong><?php echo $dns_check['connected_to']; ?></strong>.</p>
                    
                    <?php if(!empty($dns_check['missing_records'])): ?>
                        <p style="margin-top: 10px;"><strong>For comprehensive protection, consider adding these missing records:</strong></p>
                        <ul>
                            <?php foreach($dns_check['missing_records'] as $record): ?>
                                <li>Add <?php echo $record['type']; ?> record for your domain pointing to <code style="background: rgba(255,255,255,0.2); border-color: rgba(255,255,255,0.3);"><?php echo $record['value']; ?></code></li>
                            <?php endforeach; ?>
                        </ul>
                        <p>This ensures both IPv4 and IPv6 protection for maximum security.</p>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="red-info" style="background: #d80000; color: white; border: 1px solid #a00000; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                    <p><strong>⚠️ Your domain is not correctly configured for Blackwall protection</strong></p>
                    <p>Please follow the steps below to connect your domain to our protection servers:</p>
                </div>
                
                <h4>DNS Records to Add:</h4>
                <p>Add the following DNS records to your domain's DNS configuration:</p>
                
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <thead>
                        <tr>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Record Type</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Value</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Copy</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Purpose</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($dns_check['missing_records'] as $record): ?>
                            <tr>
                                <td style="border: 1px solid #ddd; padding: 8px;"><?php echo $record['type']; ?></td>
                                <td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;" id="ip-value-<?php echo $record['type']; ?>"><?php echo $record['value']; ?></td>
                                <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">
                                    <a href="javascript:void(0);" onclick="copyToClipboard('ip-value-<?php echo $record['type']; ?>')" class="copy-btn">
                                        <i class="fa fa-copy"></i>
                                    </a>
                                </td>
                                <td style="border: 1px solid #ddd; padding: 8px;">
                                    <?php echo $record['type'] == 'A' ? 'Connect to Blackwall Protection (IPv4)' : 'Connect to Blackwall Protection (IPv6)'; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <h4>Important Notes:</h4>
                <ul>
                    <li>You can choose to connect to either bg-gk-01 or bg-gk-02 node, but the same node should be used for both A and AAAA records.</li>
                    <li>DNS changes can take up to 24 hours to propagate worldwide.</li>
                    <li>After updating your DNS records, you can return to this page to check if the configuration is successful.</li>
                    <li><strong>Subdomains Protection:</strong> If you want subdomains to be protected (e.g., blog.yourdomain.com), they should also point to the same Blackwall node as your root domain.</li>
                </ul>
                
                <h4>Alternative Nodes:</h4>
                <p>You can use any of the following nodes to connect to Blackwall protection:</p>
                
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Node</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">IPv4 Record (A)</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Copy</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">IPv6 Record (AAAA)</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Copy</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php $counter = 0; foreach($gatekeeper_nodes as $node_name => $ips): $counter++; ?>
                            <tr>
                                <td style="border: 1px solid #ddd; padding: 8px;"><?php echo $node_name; ?></td>
                                <td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;" id="ipv4-<?php echo $counter; ?>"><?php echo $ips['ipv4']; ?></td>
                                <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">
                                    <a href="javascript:void(0);" onclick="copyToClipboard('ipv4-<?php echo $counter; ?>')" class="copy-btn">
                                        <i class="fa fa-copy"></i>
                                    </a>
                                </td>
                                <td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;" id="ipv6-<?php echo $counter; ?>"><?php echo $ips['ipv6']; ?></td>
                                <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">
                                    <a href="javascript:void(0);" onclick="copyToClipboard('ipv6-<?php echo $counter; ?>')" class="copy-btn">
                                        <i class="fa fa-copy"></i>
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<style>
/* Completely isolated tab system with very specific selectors */
#blackwall-tab-system {
    font-family: Arial, sans-serif;
    margin-bottom: 20px;
}

#blackwall-tab-system .blackwall-tab-buttons {
    overflow: hidden;
    border: 1px solid #ccc;
    background-color: #f1f1f1;
    display: flex;
}

#blackwall-tab-system .blackwall-tab-button {
    background-color: inherit;
    float: left;
    border: none;
    outline: none;
    cursor: pointer;
    padding: 14px 16px;
    transition: 0.3s;
    font-size: 14px;
    flex: 1;
}

#blackwall-tab-system .blackwall-tab-button i {
    margin-right: 5px;
}

#blackwall-tab-system .blackwall-tab-button:hover {
    background-color: #ddd;
}

#blackwall-tab-system .blackwall-tab-button.active {
    background-color: #fff;
    border-bottom: 2px solid #4CAF50;
    color: #4CAF50;
}

#blackwall-tab-system .blackwall-tab-content {
    display: none;
    padding: 0;
    border: 1px solid #ccc;
    border-top: none;
}

#blackwall-tab-system .blackwall-tab-content.active {
    display: block;
}

#blackwall-tab-system .blackwall-iframe-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 15px;
    background-color: #f8f8f8;
    border-bottom: 1px solid #ddd;
}

#blackwall-tab-system .blackwall-iframe-header span {
    font-weight: bold;
}

#blackwall-tab-system .refresh-btn {
    padding: 5px 10px;
    background-color: #f1f1f1;
    border: 1px solid #ddd;
    border-radius: 3px;
    cursor: pointer;
    transition: 0.3s;
}

#blackwall-tab-system .refresh-btn:hover {
    background-color: #e3e3e3;
}

#blackwall-tab-system .blackwall-tab-content iframe {
    width: 100%;
    height: 2100px; /* Increased height */
    border: none;
}

#blackwall-tab-system .padding20 {
    padding: 20px;
}

code {
    background: #f5f5f5;
    padding: 2px 5px;
    border-radius: 3px;
    border: 1px solid #ddd;
    font-family: monospace;
}

.copy-btn {
    display: inline-block;
    padding: 3px 8px;
    background: #f8f8f8;
    border: 1px solid #ddd;
    border-radius: 3px;
    cursor: pointer;
    color: #333;
    text-decoration: none;
}

.copy-btn:hover {
    background: #ebebeb;
}

.copy-notification {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: rgba(0, 0, 0, 0.7);
    color: white;
    padding: 10px 20px;
    border-radius: 5px;
    z-index: 1000;
    display: none;
}
</style>

<!-- Copy notification element -->
<div id="copy-notification" class="copy-notification">Copied to clipboard!</div>

<script>
// Completely isolated tab switching function
function openBlackwallTab(tabName) {
    // Hide all tab content
    var tabContents = document.getElementsByClassName("blackwall-tab-content");
    for (var i = 0; i < tabContents.length; i++) {
        tabContents[i].className = tabContents[i].className.replace(" active", "");
    }
    
    // Remove active class from all tab buttons
    var tabButtons = document.getElementsByClassName("blackwall-tab-button");
    for (var i = 0; i < tabButtons.length; i++) {
        tabButtons[i].className = tabButtons[i].className.replace(" active", "");
    }
    
    // Show the current tab, and add an "active" class to the button that opened the tab
    document.getElementById("blackwall-tab-" + tabName).className += " active";
    
    // Find and activate the button
    for (var i = 0; i < tabButtons.length; i++) {
        if (tabButtons[i].textContent.toLowerCase().indexOf(tabName) !== -1) {
            tabButtons[i].className += " active";
            break;
        }
    }
}

// Refresh iframe function
function refreshIframe(iframeId) {
    var iframe = document.getElementById(iframeId);
    iframe.src = iframe.src;
}

// Copy to clipboard function
function copyToClipboard(elementId) {
    var element = document.getElementById(elementId);
    var text = element.innerText;
    
    var tempInput = document.createElement("input");
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand("copy");
    document.body.removeChild(tempInput);
    
    // Show notification
    var notification = document.getElementById("copy-notification");
    notification.style.display = "block";
    
    // Highlight the copied element
    element.style.backgroundColor = "#e6ffe6";
    
    // Hide notification after 2 seconds
    setTimeout(function() {
        notification.style.display = "none";
        
        // Reset element background
        setTimeout(function() {
            element.style.backgroundColor = "";
        }, 500);
    }, 2000);
}

// Execute when page loads
document.addEventListener("DOMContentLoaded", function() {
    // First tab is active by default - no need to do anything
    console.log("Blackwall tabs initialized");
});
</script>

<div class="clear"></div>
