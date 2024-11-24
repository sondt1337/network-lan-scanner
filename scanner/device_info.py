import socket
import subprocess
import platform
import time
import requests
import netifaces

class DeviceInfo:
    def __init__(self):
        self.vendor_cache = {}
        self.mac_cache = {}
        self.timeout = 0.5

    def check_device_alive(self, ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            ping_result = subprocess.call(
                ['ping', param, '1', str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ) == 0
            
            if ping_result:
                return True
                
            common_ports = [80, 443, 22, 8080]
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(self.timeout)
                        if sock.connect_ex((str(ip), port)) == 0:
                            return True
                except:
                    continue
            return False
        except:
            return False

    def get_mac_address(self, ip):
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

    def get_vendor(self, mac_address):
        if not mac_address or mac_address == "N/A":
            return "N/A"
            
        try:
            if mac_address in self.vendor_cache:
                return self.vendor_cache[mac_address]
                
            mac = mac_address.replace(':', '').upper()[:6]
            url = f"https://api.macvendors.com/{mac}"
            
            max_retries = 20
            retry_delay = 3
            
            for attempt in range(max_retries):
                try:
                    response = requests.get(url, timeout=2)
                    
                    if response.status_code == 200:
                        vendor = response.text
                        self.vendor_cache[mac_address] = vendor
                        return vendor
                    elif response.status_code == 429:
                        time.sleep(retry_delay * 2)
                        continue
                    else:
                        if attempt < max_retries - 1:
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