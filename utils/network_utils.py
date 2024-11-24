import ipaddress
import netifaces

def get_local_networks():
    networks = []
    interfaces = netifaces.interfaces()
    
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if 'addr' in addr and 'netmask' in addr:
                    try:
                        network = ipaddress.IPv4Network(
                            f"{addr['addr']}/{addr['netmask']}", 
                            strict=False
                        )
                        if not network.is_private:
                            continue
                        
                        # Get MAC address
                        mac = None
                        if netifaces.AF_LINK in addrs:
                            mac = addrs[netifaces.AF_LINK][0].get('addr', 'N/A')
                        
                        # Determine interface type
                        interface_type = 'Wireless' if 'wlan' in iface else 'Wired'
                        
                        # Check connection status (assumed)
                        is_connected = True  # Need to add logic to check actual status
                        
                        networks.append({
                            'network': str(network),
                            'interface': iface,
                            'mac': mac,
                            'type': interface_type,
                            'connected': is_connected
                        })
                    except:
                        continue
    return networks