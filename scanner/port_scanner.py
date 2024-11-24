import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from config.ports import COMMON_PORTS

class PortScanner:
    def __init__(self, timeout=0.5):
        self.timeout = timeout

    def check_port(self, ip, port_info):
        port, service = port_info
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((str(ip), port)) == 0:
                    return f"{port}({service})"
        except:
            pass
        return None

    def scan_ports(self, ip):
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.check_port, ip, (port, service))
                for port, service in COMMON_PORTS.items()
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except:
                    continue
                    
        return open_ports