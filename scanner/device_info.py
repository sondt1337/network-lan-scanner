import socket
import platform
import time
import requests
import netifaces
from ping3 import ping
from scapy.all import ARP, Ether, srp
import logging
from getmac import get_mac_address

class DeviceInfo:
    def __init__(self):
        self.vendor_cache = {}
        self.mac_cache = {}
        self.timeout = 0.5
        logging.basicConfig(level=logging.INFO)

    def check_device_alive(self, ip):
        try:
            response = ping(str(ip), timeout=self.timeout)
            if response is not None:
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
        except Exception as e:
            logging.error(f"Error checking if device is alive: {e}")
            return False

    def get_mac_address(self, ip):
        if ip in self.mac_cache:
            return self.mac_cache[ip]

        try:
            mac = get_mac_address(ip=str(ip))
            if mac:
                self.mac_cache[ip] = mac
                return mac
        except Exception as e:
            logging.error(f"Error when getting MAC for {ip}: {str(e)}")
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
                    logging.error(f"Connection API error (attempt {attempt + 1}): {str(e)}")
                    if attempt < max_retries - 1:
                        logging.info(f"Retry after {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        continue

            logging.warning(f"Exceeded retry limit for MAC {mac_address}")
            return "Unknown"

        except Exception as e:
            logging.error(f"Unexpected error when getting vendor for MAC {mac_address}: {str(e)}")
            return "Unknown"