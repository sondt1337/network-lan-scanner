import ipaddress
import subprocess
import socket
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import time
from tabulate import tabulate
import requests

class NetworkScanner:
    def __init__(self, network, num_threads=50):
        self.network = network
        self.num_threads = num_threads
        self.timeout = 0.5
        self.devices_found = 0
        self.start_time = None
        self.known_devices = {
            '192.168.1.1': 'Router',
            '192.168.1.254': 'Router',
            '192.168.0.1': 'Router'
        }
        self.vendor_cache = {}
        self.mac_cache = {}
        self.results = []
        # Get local IP
        self.local_ip = self.get_local_ip()
        
    def get_local_ip(self):
       try:
           s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
           s.connect(("8.8.8.8", 80))
           local_ip = s.getsockname()[0]
           s.close()
           return local_ip
       except:
           return None
    def get_local_mac(self):
       try:
           interfaces = netifaces.interfaces()
           for iface in interfaces:
               addrs = netifaces.ifaddresses(iface)
               if netifaces.AF_LINK in addrs:  # get MAC address
                   mac = addrs[netifaces.AF_LINK][0]['addr']
                   if mac and mac != "00:00:00:00:00:00":
                       return mac.upper()
       except Exception as e:
           print(f"Lỗi khi lấy MAC local: {str(e)}")
       return None
    
    def get_vendor(self, mac_address):
        if not mac_address or mac_address == "N/A":
            return "N/A"
        
        try:
            # Check cache before
            if mac_address in self.vendor_cache:
                return self.vendor_cache[mac_address]
            
            mac = mac_address.replace(':', '').upper()[:6]
            url = f"https://api.macvendors.com/{mac}"
            
            max_retries = 20
            retry_delay = 3  # Delay 3 seconds between retries
            
            for attempt in range(max_retries):
                try:
                    response = requests.get(url, timeout=2)
                    
                    if response.status_code == 200:
                        vendor = response.text
                        self.vendor_cache[mac_address] = vendor
                        return vendor
                    elif response.status_code == 429:  # Rate limit
                        time.sleep(retry_delay * 2)  # Increase delay if rate limited
                        continue
                    else:
                        if attempt < max_retries - 1:  # If there is a retry
                            time.sleep(retry_delay)
                            continue
                except requests.exceptions.RequestException as e:
                    print(f"Connection API error (attempt {attempt + 1}): {str(e)}")
                    if attempt < max_retries - 1:
                        print(f"Retry after {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        continue
            
            print(f"Exceeded retry limit for MAC {mac_address}")
            return "Unknown"
            
        except Exception as e:
            print(f"Unexpected error when getting vendor for MAC {mac_address}: {str(e)}")
            return "Unknown"

    def get_mac_address(self, ip):
       # Check cache before
       if ip in self.mac_cache:
           return self.mac_cache[ip]
       try:
           param = '-n' if platform.system().lower() == 'windows' else '-c'
           subprocess.call(
               ['ping', param, '1', str(ip)],
               stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL
           )
           
           time.sleep(0.4)
           
           if platform.system().lower() == 'windows':
               result = subprocess.check_output(['arp', '-a', str(ip)], text=True)
               for line in result.split('\n'):
                   if str(ip) in line:
                       parts = line.split()
                       if len(parts) >= 2:
                           mac = parts[1].strip()
                           if mac != "ff-ff-ff-ff-ff-ff" and mac != "<incomplete>":
                               mac = mac.replace('-', ':').upper()
                               self.mac_cache[ip] = mac
                               return mac
           else:
               result = subprocess.check_output(['arp', '-n', str(ip)], text=True)
               for line in result.split('\n'):
                   if str(ip) in line:
                       parts = line.split()
                       if len(parts) >= 3:
                           mac = parts[2].strip().upper()
                           if mac != "FF:FF:FF:FF:FF:FF" and mac != "<INCOMPLETE>":
                               self.mac_cache[ip] = mac
                               return mac
       except Exception as e:
           print(f"Error when getting MAC for {ip}: {str(e)}")
       return None

    def scan_ports(self, ip):
       common_ports = {
            # Web Services
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt', 8888: 'HTTP-Alt', 81: 'HTTP-Alt', 3000: 'Dev-HTTP',
            4443: 'HTTPS-Alt', 8081: 'HTTP-Alt', 8082: 'HTTP-Alt', 9443: 'HTTPS-Alt',
            5000: 'Flask', 5001: 'Flask-Alt', 16080: 'Alt-HTTP', 18080: 'HTTP-Testing',
            
            # Email Services
            25: 'SMTP', 465: 'SMTPS', 587: 'SMTP-SUB',
            110: 'POP3', 995: 'POP3S',
            143: 'IMAP', 993: 'IMAPS', 2525: 'SMTP-Testing', 4190: 'Sieve',
            
            # File Transfer
            20: 'FTP-DATA', 21: 'FTP', 989: 'FTPS-DATA', 990: 'FTPS',
            22: 'SSH/SFTP', 69: 'TFTP', 115: 'SFTP', 2048: 'FTP-Alt',
            2121: 'FTP-Alt2', 6666: 'IRC-FileTransfer',
            
            # Remote Access
            22: 'SSH', 23: 'TELNET', 3389: 'RDP', 5900: 'VNC',
            5901: 'VNC-1', 5902: 'VNC-2', 5903: 'VNC-3', 2222: 'SSH-Alt',
            7000: 'RDP-Alt', 32768: 'VNC-HighPort',
            
            # Database Services
            1433: 'MSSQL', 1434: 'MSSQL-UDP', 3306: 'MySQL',
            5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis',
            5984: 'CouchDB', 9200: 'Elasticsearch', 1521: 'Oracle-DB',
            27018: 'MongoDB-Alt', 50000: 'DB2', 50001: 'DB2-Alt',
            33060: 'MySQLX', 2484: 'Oracle-TNS', 49152: 'MSSQL-Alt',

            # Directory Services
            389: 'LDAP', 636: 'LDAPS', 88: 'Kerberos', 3268: 'Global-Catalog',
            3269: 'Global-Catalog-SSL', 500: 'IKE', 4500: 'IPSec-NAT',
            
            # Network Services
            53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client',
            123: 'NTP', 161: 'SNMP', 162: 'SNMP-TRAP',
            520: 'RIP', 179: 'BGP', 119: 'NNTP', 500: 'ISAKMP',
            5353: 'mDNS', 16161: 'SNMP-Alt',
            
            # File Sharing
            445: 'SMB', 139: 'NetBIOS', 137: 'NetBIOS-NS',
            138: 'NetBIOS-DGM', 2049: 'NFS', 111: 'RPC', 873: 'Rsync',
            135: 'MSRPC', 49153: 'SMB-Alt', 49154: 'SMB-Alt2',
            
            # Messaging & Communication
            5060: 'SIP', 5061: 'SIPS', 1900: 'UPNP',
            5222: 'XMPP', 5269: 'XMPP-Server', 3478: 'STUN',
            19302: 'TURN', 6667: 'IRC', 6697: 'IRC-SSL',
            
            # Media Streaming
            554: 'RTSP', 1935: 'RTMP', 8554: 'RTSP-Alt',
            7070: 'RealPlayer', 8001: 'Streaming-Alt',
            12345: 'Media-Test', 12346: 'Media-Test2',
            
            # IoT & Smart Devices
            1883: 'MQTT', 8883: 'MQTT-SSL', 5683: 'CoAP',
            5353: 'mDNS', 49152: 'UPnP', 4840: 'OPC-UA',
            
            # Development
            9000: 'Node', 4200: 'Angular', 5173: 'Vite',
            8545: 'Ethereum', 9090: 'Prometheus', 8765: 'WebSockets',
            3001: 'React-Dev', 8002: 'Custom-Dev', 1337: 'Testing',
            
            # Monitoring & Management
            161: 'SNMP', 162: 'SNMP-Trap', 10050: 'Zabbix-Agent',
            10051: 'Zabbix-Server', 8086: 'InfluxDB', 9182: 'Node-Exporter',
            9093: 'Alertmanager', 6000: 'X11', 2003: 'Graphite',
            
            # Proxy & Load Balancing
            3128: 'Squid', 8080: 'HTTP-Proxy', 9090: 'HAProxy',
            8444: 'Tomcat', 8009: 'AJP', 1080: 'SOCKS',
            
            # Game Servers
            25565: 'Minecraft', 27015: 'Source', 7777: 'Terraria',
            27005: 'Steam', 19132: 'Minecraft-Bedrock', 2302: 'Arma',
            8880: 'Unreal-Tournament',
            
            # Virtualization
            902: 'VMware', 2375: 'Docker', 2376: 'Docker-SSL',
            6443: 'Kubernetes-API', 16509: 'Libvirt', 3260: 'iSCSI',
            
            # Security
            8834: 'Nessus', 9390: 'OpenVAS', 8080: 'Webmin',
            1337: 'Metasploit', 4444: 'Payload', 2323: 'Telnet-Alt',
            
            # Misc Services
            111: 'RPC', 514: 'Syslog', 5000: 'UPnP',
            1194: 'OpenVPN', 1701: 'L2TP', 1723: 'PPTP',
            1812: 'RADIUS', 5938: 'TeamViewer', 3283: 'Apple-Remote',
            5357: 'WSDAPI', 8291: 'Mikrotik-API', 24800: 'TeamSpeak',
            26000: 'Quake', 113: 'Ident', 631: 'IPP',
            42: 'WINS', 88: 'Kerberos', 5355: 'LLMNR',
            13722: 'BackupExec', 51413: 'Transmission',
        }


       open_ports = []
       def check_port(port_info):
            port, service = port_info
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((str(ip), port)) == 0:
                        return f"{port}({service})"
            except:
                pass
            return None
       with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_port, (port, service)) 
                        for port, service in common_ports.items()]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except:
                    continue
               
       return open_ports

    def scan_ip(self, ip):
       try:
           is_alive = False
           
           # Check ping
           param = '-n' if platform.system().lower() == 'windows' else '-c'
           ping_result = subprocess.call(
               ['ping', param, '1', str(ip)],
               stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL
           ) == 0
           
           if ping_result:
               is_alive = True
           else:
               # Check common ports
               common_ports = [80, 443, 22, 8080]
               for port in common_ports:
                   try:
                       with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                           sock.settimeout(self.timeout)
                           if sock.connect_ex((str(ip), port)) == 0:
                               is_alive = True
                               break
                   except:
                       continue
           if is_alive:
               # Increase wait time and add retry
               time.sleep(1)
               
               # Process MAC address
               mac = None
               if str(ip) == self.local_ip:
                   mac = self.get_local_mac()
               else:
                   max_retries = 3
                   for attempt in range(max_retries):
                       mac = self.get_mac_address(str(ip))
                       if mac:
                           break
                       time.sleep(0.5)
                       print(f"Retry {attempt + 1} to get MAC of {ip}")
               vendor = self.get_vendor(mac) if mac else "N/A"
               open_ports = self.scan_ports(ip)
               
               device_info = {
                   'ip': str(ip),
                   'mac': mac if mac else "N/A",
                   'vendor': vendor,
                   'ports': ', '.join(open_ports) if open_ports else "N/A"
               }
               
               print(f"{device_info}")
               return device_info
       except Exception as e:
           print(f"Error when scanning {ip}: {str(e)}")
       return None

    def scan(self):
        print("\nScanning network, please wait...")
        self.start_time = time.time()
        network = ipaddress.ip_network(self.network)

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(self.scan_ip, ip) for ip in network.hosts()]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        self.devices_found += 1
                except Exception as e:
                    continue

        self.results.sort(key=lambda x: list(map(int, x['ip'].split('.'))))
        
        headers = ['IP', 'MAC', 'Vendor', 'Open Ports']
        table_data = [[
            r['ip'],
            r['mac'],
            r['vendor'],
            r['ports']
        ] for r in self.results]
        
        print("\nScanning results:")
        print(tabulate(table_data, headers=headers, tablefmt='grid'))

        duration = time.time() - self.start_time
        print(f"\nStatistics:")
        print(f"- Scanning time: {duration:.2f} seconds")
        print(f"- Number of devices found: {self.devices_found}")

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

def main():
    try:
        print("\n=== Network Scanner v3.0 ===")
        networks = get_local_networks()
        
        if not networks:
            print("No network found!")
            return

        print("\nAvailable networks:")
        for idx, net in enumerate(networks, 1):
            print(f"{idx}. {net['network']} (Interface: {net['interface']})")

        while True:
            try:
                choice = int(input("\nSelect network to scan (enter number): ")) - 1
                if 0 <= choice < len(networks):
                    break
                print("Invalid choice!")
            except ValueError:
                print("Please enter a number!")

        scanner = NetworkScanner(networks[choice]['network'])
        scanner.scan()

    except KeyboardInterrupt:
        print("\n\nScanning stopped by user!")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
