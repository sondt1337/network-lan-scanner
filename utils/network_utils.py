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
                        networks.append({
                            'network': str(network),
                            'interface': iface
                        })
                    except:
                        continue
    return networks