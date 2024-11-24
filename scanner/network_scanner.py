import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate

from utils.system_utils import get_local_ip, get_local_mac
from scanner.device_info import DeviceInfo
from scanner.port_scanner import PortScanner

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
        self.results = []
        self.local_ip = get_local_ip()
        self.device_info = DeviceInfo()
        self.port_scanner = PortScanner(timeout=self.timeout)

    def scan_ip(self, ip):
        try:
            is_alive = self.device_info.check_device_alive(ip)
            
            if is_alive:
                time.sleep(1)
                
                mac = None
                if str(ip) == self.local_ip:
                    mac = get_local_mac()
                else:
                    max_retries = 3
                    for attempt in range(max_retries):
                        mac = self.device_info.get_mac_address(str(ip))
                        if mac:
                            break
                        time.sleep(0.5)
                        print(f"Retry {attempt + 1} to get MAC of {ip}")
                
                vendor = self.device_info.get_vendor(mac) if mac else "N/A"
                open_ports = self.port_scanner.scan_ports(ip)
                
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
                    if result and (result['mac'] != "N/A" or result['ports'] != "N/A"):
                        self.results.append(result)
                        self.devices_found += 1
                except Exception:
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