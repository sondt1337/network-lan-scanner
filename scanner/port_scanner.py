import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from config.ports import COMMON_PORTS

class PortScanner:
    def __init__(self, timeout=0.5, max_workers=20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.banner_grab = True

    def check_port(self, ip, port_info):
        port, service = port_info
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((str(ip), port))
                if result == 0:
                    banner = self.grab_banner(ip, port) if self.banner_grab else None
                    if banner:
                        return f"{port}({service} - {banner})"
                    return f"{port}({service})"
        except:
            pass
        return None
    
    def grab_banner(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout * 2)
                sock.connect((str(ip), port))
                
                # Common protocols that respond to different prompts
                if port in [21, 25, 110, 143]:  # FTP, SMTP, POP3, IMAP
                    # These protocols usually send a banner upon connection
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 80 or port == 443 or port == 8080:  # HTTP/HTTPS
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + str(ip).encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                elif port == 22:  # SSH
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                else:
                    # Try a generic approach for other ports
                    sock.send(b"\r\n")
                    time.sleep(0.1)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if banner:
                    # Limit banner length and clean it
                    return banner[:40].replace('\n', ' ').replace('\r', '')
        except:
            pass
        return None

    def scan_ports(self, ip, custom_ports=None):
        open_ports = []
        ports_to_scan = custom_ports or COMMON_PORTS.items()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self.check_port, ip, (port, service))
                for port, service in ports_to_scan
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except:
                    continue
                    
        return open_ports