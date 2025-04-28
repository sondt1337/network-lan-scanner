import requests
import socket
import sys
import concurrent.futures
import ipaddress
import re
import json
import time
import argparse
from urllib.parse import urlparse, quote_plus

# Terminal colors for better readability
if sys.stdout.isatty():
    R = '\033[31m'  # Red
    G = '\033[32m'  # Green
    C = '\033[36m'  # Cyan
    W = '\033[0m'   # Reset
    Y = '\033[33m'  # Yellow
    M = '\033[35m'  # Magenta
    B = '\033[34m'  # Blue
else:
    R = G = C = W = Y = M = B = ''  # No color in non-TTY environments

# ========== CONFIGURATION ==========
# Standard IP Camera Ports
COMMON_PORTS = [80, 81, 82, 83, 443, 554, 1935, 7001, 8000, 8080, 8081, 8443, 8888, 9000]

# Camera Admin Pages and API endpoints
COMMON_PATHS = [
    "/", "/admin", "/login", "/viewer", "/webadmin", "/video", "/stream", "/view/view.shtml",
    "/index.html", "/cgi-bin/viewer/video.jpg", "/control/control.html", "/live.html",
    "/mjpg/video.mjpg", "/api/v1/status", "/onvif/device_service", "/axis-cgi/mjpg/video.cgi"
]

# Default credentials for common camera brands
DEFAULT_CREDENTIALS = {
    "admin": ["admin", "1234", "password", "12345", "123456", "admin123", "4321", "888888"],
    "root": ["root", "pass", "toor", "12345", "admin"],
    "user": ["user", "123456", "user123"],
    "supervisor": ["supervisor", "12345"],
    "hikvision": ["hikvision", "12345"],
    "dahua": ["dahua", "admin123"],
    "axis": ["pass", "axis2022"],
    "operator": ["operator", "12345"],
    "guest": ["guest", "12345", ""],
}

# Camera brand signatures in headers and HTML content
CAMERA_SIGNATURES = {
    "hikvision": {
        "headers": ["hikvision", "webdvr"],
        "content": ["hikvision", "dvr webservice", "hikvision digital technology"],
        "vulnerabilities": [
            "CVE-2021-36260 - Command Injection",
            "CVE-2017-7921 - Authentication Bypass"
        ]
    },
    "dahua": {
        "headers": ["dahua"],
        "content": ["dahua technology", "dahuasecurity", "dahua dss"],
        "vulnerabilities": [
            "CVE-2021-33044 - Authentication Bypass",
            "CVE-2022-25078 - Command Injection"
        ]
    },
    "axis": {
        "headers": ["axis", "boa/"],
        "content": ["axis communications", "axis2", "axiscam"],
        "vulnerabilities": [
            "CVE-2018-10660 - Command Injection",
            "CVE-2023-23300 - Authentication Bypass"
        ]
    },
    "foscam": {
        "headers": ["foscam"],
        "content": ["foscam", "ipcam client"],
        "vulnerabilities": [
            "CVE-2018-19355 - Authentication Bypass",
            "CVE-2020-9047 - Command Injection"
        ]
    },
    "amcrest": {
        "headers": ["amcrest"],
        "content": ["amcrest", "amcrestview"],
        "vulnerabilities": [
            "CVE-2017-8229 - Information Disclosure",
            "CVE-2019-3948 - Authentication Bypass"
        ]
    },
    "wyze": {
        "headers": ["wyze"],
        "content": ["wyze", "wyzecam"],
        "vulnerabilities": [
            "CVE-2019-9569 - Information Disclosure"
        ]
    },
    "reolink": {
        "headers": ["reolink"],
        "content": ["reolink", "baichuan"],
        "vulnerabilities": [
            "CVE-2020-25169 - Authentication Bypass",
            "CVE-2021-40150 - Command Injection"
        ]
    }
}

# ========== UTILITY FUNCTIONS ==========
def print_status(message, status="info"):
    """Print formatted status messages"""
    if status == "info":
        print(f"[ℹ️] {C}{message}{W}")
    elif status == "success":
        print(f"[✅] {G}{message}{W}")
    elif status == "error":
        print(f"[❌] {R}{message}{W}")
    elif status == "warning":
        print(f"[⚠️] {Y}{message}{W}")
    elif status == "scanning":
        print(f"[🔍] {C}{message}{W}")
    elif status == "found":
        print(f"[🔥] {M}{message}{W}")

def validate_ip(ip):
    """Validate if the input is a valid IP address or CIDR range"""
    try:
        if "/" in ip:  # CIDR notation
            ipaddress.ip_network(ip, strict=False)
            return True
        else:  # Single IP
            ipaddress.ip_address(ip)
            return True
    except ValueError:
        return False

def expand_cidr(cidr):
    """Expand CIDR notation to list of IPs"""
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
    except ValueError:
        print_status(f"Invalid CIDR notation: {cidr}", "error")
        return []

# ========== SEARCH & INFORMATION FUNCTIONS ==========
def print_search_urls(ip):
    """Generate URLs for manual search in security search engines"""
    print_status("Use these URLs to check the camera exposure manually:", "info")
    print(f"  🔹 Shodan: https://www.shodan.io/search?query={ip}")
    print(f"  🔹 Censys: https://search.censys.io/hosts/{ip}")
    print(f"  🔹 Zoomeye: https://www.zoomeye.org/searchResult?q={ip}")
    print(f"  🔹 Fofa: https://fofa.info/result?qbase64={quote_plus(f'ip=\"{ip}\"')}")
    print(f"  🔹 Google Dorking: https://www.google.com/search?q=site:{ip}+inurl:view/view.shtml+OR+inurl:admin.html+OR+inurl:login")

def google_dork_search(ip):
    """Generate Google dork queries for finding camera interfaces"""
    print_status("Google Dorking Suggestions:", "info")
    queries = [
        f"site:{ip} inurl:view/view.shtml",
        f"site:{ip} inurl:admin.html",
        f"site:{ip} inurl:login",
        f"intitle:'webcam' inurl:{ip}",
        f"intitle:'live view' inurl:{ip}",
        f"intitle:'AXIS' inurl:{ip}",
        f"intitle:'Hikvision' inurl:{ip}",
        f"intitle:'Dahua' inurl:{ip}",
        f"intitle:'camera' inurl:{ip}",
    ]

    for q in queries:
        print(f"  🔍 Google Dork: https://www.google.com/search?q={q.replace(' ', '+')}")

def check_ipinfo(ip):
    """Retrieve geolocation and ISP information for the target IP"""
    print_status("Checking Public IP Information (ipinfo.io):", "info")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"  IP: {data['ip']}")
            print(f"  City: {data.get('city', 'N/A')}")
            print(f"  Region: {data.get('region', 'N/A')}")
            print(f"  Country: {data.get('country', 'N/A')}")
            print(f"  ISP: {data.get('org', 'N/A')}")
            print(f"  Location: {data.get('loc', 'N/A')}")
            print(f"  Timezone: {data.get('timezone', 'N/A')}")
            
            # Check if IP is in known datacenter ranges
            if "hosting" in data.get('org', '').lower() or "cloud" in data.get('org', '').lower():
                print_status("This IP appears to be from a hosting provider or datacenter, less likely to be a home camera", "warning")
        else:
            print_status("Failed to fetch IP information", "error")
    except Exception as e:
        print_status(f"IP Info Error: {e}", "error")

# ========== SCANNING FUNCTIONS ==========
def check_ports(ip, timeout=1, max_workers=10):
    """Scan for open ports using multi-threading for faster results"""
    print_status(f"Scanning common CCTV ports on IP: {ip}", "scanning")
    open_ports = []

    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(check_port, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    print(f"  🔄 Port {port}: {G}OPEN!{W}")
                    open_ports.append(port)
                else:
                    print(f"  🔄 Port {port}: {R}CLOSED{W}")
            except Exception as e:
                print(f"  🔄 Port {port}: {R}ERROR - {e}{W}")

    if open_ports:
        print_status(f"Found {len(open_ports)} open ports: {', '.join(map(str, open_ports))}", "success")
    else:
        print_status("No open ports found", "warning")

    return open_ports

def check_if_camera(ip, open_ports, timeout=3):
    """Check if the device is likely a camera by analyzing responses"""
    print_status("Checking if the device is a CAMERA:", "scanning")
    
    found_camera = False
    camera_evidence = []
    
    for port in open_ports:
        # Try HTTP and HTTPS
        for protocol in ["http", "https"]:
            url = f"{protocol}://{ip}:{port}"
            print(f"  🔄 Testing {url}...", end=" ")
            
            try:
                response = requests.get(url, timeout=timeout, verify=False)
                content_type = response.headers.get("Content-Type", "")
                server = response.headers.get("Server", "")
                
                # Check content type for image/video streams
                if "image" in content_type or "video" in content_type or "mjpeg" in content_type.lower():
                    print(f"{G}✅ Camera Stream Found!{W}")
                    found_camera = True
                    camera_evidence.append(f"Stream detected at {url} ({content_type})")
                
                # Check for camera-related keywords in response
                elif response.status_code == 200:
                    html_content = response.text.lower()
                    camera_keywords = ["camera", "webcam", "ipcam", "surveillance", "cctv", "dvr", "nvr", 
                                      "hikvision", "dahua", "axis", "foscam", "amcrest", "rtsp", "onvif"]
                    
                    matches = [keyword for keyword in camera_keywords if keyword in html_content or keyword in server.lower()]
                    
                    if matches:
                        print(f"{G}✅ Camera Interface Found! Keywords: {', '.join(matches)}{W}")
                        found_camera = True
                        camera_evidence.append(f"Camera interface at {url} (Keywords: {', '.join(matches)})")
                    else:
                        print(f"{R}❌ Not a Camera{W}")
                else:
                    print(f"{R}❌ No Response (Status: {response.status_code}){W}")
            
            except requests.exceptions.SSLError:
                print(f"{Y}⚠️ SSL Error - Try HTTP instead{W}")
            except Exception as e:
                print(f"{R}❌ Error: {str(e)[:30]}...{W}")
    
    if found_camera:
        print_status("Evidence suggesting this is a camera:", "success")
        for evidence in camera_evidence:
            print(f"  ✓ {evidence}")
    else:
        print_status("No camera evidence detected", "warning")
    
    return found_camera, camera_evidence

def check_login_pages(ip, open_ports, timeout=3):
    """Check for camera login pages and admin interfaces"""
    print_status("Checking for Camera Login Pages:", "scanning")
    possible_cameras = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        
        for port in open_ports:
            for path in COMMON_PATHS:
                # Try both HTTP and HTTPS
                for protocol in ["http", "https"]:
                    url = f"{protocol}://{ip}:{port}{path}"
                    futures.append(executor.submit(check_url, url, timeout))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                url, status_code, server, title = result
                possible_cameras.append(result)
                status_text = f"{G}✅ Found!{W}"
                if title:
                    status_text += f" Title: {title}"
                if server:
                    status_text += f" Server: {server}"
                print(f"  🔄 {url} - {status_text}")
    
    if possible_cameras:
        print_status(f"Found {len(possible_cameras)} potential camera interfaces", "success")
    else:
        print_status("No camera login pages detected", "warning")
    
    return possible_cameras

def check_url(url, timeout):
    """Helper function to check a URL for camera interfaces"""
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        if response.status_code == 200:
            server = response.headers.get("Server", "")
            
            # Extract title if available
            title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
            title = title_match.group(1) if title_match else ""
            
            return (url, response.status_code, server, title)
    except:
        pass
    return None

def check_camera_firmware(ip, open_ports, timeout=3):
    """Identify camera type, firmware and known vulnerabilities"""
    print_status("Checking for Camera Type & Known Vulnerabilities:", "scanning")
    
    detected_cameras = []
    
    for port in open_ports:
        # Try both HTTP and HTTPS
        for protocol in ["http", "https"]:
            url = f"{protocol}://{ip}:{port}"
            print(f"  🔄 Scanning {url}...", end=" ")
            
            try:
                response = requests.get(url, timeout=timeout, verify=False)
                headers = response.headers
                content = response.text.lower()
                
                # Check for camera signatures in headers and content
                for brand, signatures in CAMERA_SIGNATURES.items():
                    # Check headers
                    header_match = any(sig in headers.get("Server", "").lower() for sig in signatures["headers"])
                    
                    # Check content
                    content_match = any(sig in content for sig in signatures["content"])
                    
                    if header_match or content_match:
                        print(f"{M}🔥 {brand.capitalize()} Camera Detected!{W}")
                        
                        # Print known vulnerabilities
                        if signatures.get("vulnerabilities"):
                            print(f"    {Y}Potential Vulnerabilities:{W}")
                            for vuln in signatures["vulnerabilities"]:
                                print(f"    ⚠️ {vuln}")
                        
                        detected_cameras.append((brand, url))
                        break
                else:
                    # No specific camera detected, check generic signatures
                    if "server" in headers:
                        print(f"{Y}⚠️ Unknown Camera Type - Server: {headers['server']}{W}")
                    else:
                        print(f"{R}❌ No Camera Signature Found{W}")
            
            except requests.exceptions.SSLError:
                print(f"{Y}⚠️ SSL Error - Try HTTP instead{W}")
            except Exception as e:
                print(f"{R}❌ Error: {str(e)[:30]}...{W}")
    
    return detected_cameras

def test_default_passwords(ip, open_ports, timeout=3):
    """Test default credentials on camera login pages"""
    print_status("Testing Default Camera Passwords:", "scanning")
    
    vulnerable_endpoints = []
    
    for port in open_ports:
        # Try common login endpoints
        login_paths = ["/login", "/admin", "/", "/cgi-bin/login.cgi", "/Login.htm"]
        
        for path in login_paths:
            # Try both HTTP and HTTPS
            for protocol in ["http", "https"]:
                url = f"{protocol}://{ip}:{port}{path}"
                print(f"  🔄 Testing {url}...")
                
                for username, passwords in DEFAULT_CREDENTIALS.items():
                    for password in passwords:
                        try:
                            # Try both form-based and basic auth
                            # Form-based auth
                            form_data = {
                                "username": username,
                                "password": password,
                                "user": username,
                                "pass": password,
                                "login": "Login"
                            }
                            
                            response = requests.post(url, data=form_data, timeout=timeout, verify=False, allow_redirects=False)
                            
                            # Check for successful login indicators
                            if response.status_code in [200, 302] and not ("login" in response.text.lower() and "password" in response.text.lower()):
                                print(f"  {M}🔥 Potentially Vulnerable! Form Auth: {username}/{password}{W}")
                                vulnerable_endpoints.append((url, "form", username, password))
                                break
                            
                            # Basic auth
                            response = requests.get(url, auth=(username, password), timeout=timeout, verify=False)
                            if response.status_code == 200 and not ("login" in response.text.lower() and "password" in response.text.lower()):
                                print(f"  {M}🔥 Potentially Vulnerable! Basic Auth: {username}/{password}{W}")
                                vulnerable_endpoints.append((url, "basic", username, password))
                                break
                                
                        except:
                            pass  # Ignore errors
    
    if vulnerable_endpoints:
        print_status(f"Found {len(vulnerable_endpoints)} potentially vulnerable endpoints with default credentials!", "found")
        for url, auth_type, username, password in vulnerable_endpoints:
            print(f"  🔑 {url} - {auth_type.capitalize()} Auth: {username}/{password}")
    else:
        print_status("No default credentials found or login attempts failed", "warning")
    
    return vulnerable_endpoints

def check_rtsp_streams(ip, timeout=3):
    """Check for open RTSP streams"""
    print_status("Checking for RTSP Streams:", "scanning")
    
    # Common RTSP ports
    rtsp_ports = [554, 8554, 10554]
    
    # Common RTSP paths
    rtsp_paths = [
        "/", "/live", "/live/ch00_0", "/live/ch01_0", "/live/main", "/live/sub",
        "/cam/realmonitor", "/cam0", "/cam1", "/ch0", "/ch1", "/video1", "/video.mp4",
        "/11", "/12", "/h264", "/mpeg4", "/av0_0", "/av0_1"
    ]
    
    potential_streams = []
    
    for port in rtsp_ports:
        for path in rtsp_paths:
            rtsp_url = f"rtsp://{ip}:{port}{path}"
            print(f"  🔄 Checking {rtsp_url}...")
            
            # We can't easily test RTSP streams without a player, so we'll just suggest them
            potential_streams.append(rtsp_url)
    
    if potential_streams:
        print_status("Potential RTSP streams to try with a media player like VLC:", "info")
        for stream in potential_streams[:10]:  # Limit to 10 suggestions
            print(f"  🎥 {stream}")
        
        if len(potential_streams) > 10:
            print(f"  ... and {len(potential_streams) - 10} more possibilities")
    
    return potential_streams

def check_onvif_discovery(ip, timeout=3):
    """Check if the camera supports ONVIF discovery protocol"""
    print_status("Checking for ONVIF Support:", "scanning")
    
    # ONVIF discovery message (WS-Discovery)
    onvif_discovery_msg = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:84ede3de-7dec-11d0-c360-F01234567890</w:MessageID>
    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""
    
    # Try common ONVIF ports
    onvif_ports = [80, 8000, 8080, 8081, 8899]
    
    for port in onvif_ports:
        url = f"http://{ip}:{port}/onvif/device_service"
        print(f"  🔄 Testing ONVIF at {url}...")
        
        try:
            response = requests.post(url, data=onvif_discovery_msg, 
                                    headers={"Content-Type": "application/soap+xml"}, 
                                    timeout=timeout)
            
            if "onvif" in response.text.lower():
                print(f"  {G}✅ ONVIF supported at {url}{W}")
                return True
        except:
            pass
    
    print_status("No ONVIF support detected", "warning")
    return False

# ========== MAIN FUNCTION ==========
def main():
    parser = argparse.ArgumentParser(description="Camera Exploitation & Exposure Scanner")
    parser.add_argument("target", nargs="?", help="Target IP address or CIDR range")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for requests in seconds")
    parser.add_argument("-p", "--ports", help="Custom ports to scan (comma-separated)")
    parser.add_argument("--no-vuln-check", action="store_true", help="Skip vulnerability checking")
    parser.add_argument("--no-password-check", action="store_true", help="Skip default password checking")
    
    args = parser.parse_args()
    
    # Get target IP from args or prompt
    if args.target:
        target_ip = args.target
    else:
        target_ip = input(f"{G}[+] {C}Enter Potential Public IP or CIDR range of the Camera: {W}").strip()
    
    # Use custom ports if specified
    if args.ports:
        try:
            global COMMON_PORTS
            COMMON_PORTS = [int(p) for p in args.ports.split(",")]
            print_status(f"Using custom ports: {COMMON_PORTS}", "info")
        except:
            print_status("Invalid port specification, using default ports", "warning")
    
    # Handle CIDR notation
    if "/" in target_ip:
        ips = expand_cidr(target_ip)
        if not ips:
            return
        
        print_status(f"Scanning {len(ips)} IP addresses in range {target_ip}", "info")
        
        for i, ip in enumerate(ips):
            print(f"\n{Y}{'='*60}{W}")
            print(f"{Y}[{i+1}/{len(ips)}] Scanning {ip}{W}")
            print(f"{Y}{'='*60}{W}\n")
            
            scan_single_ip(ip, args)
            
            # Small delay between IPs to avoid overwhelming the network
            if i < len(ips) - 1:
                time.sleep(1)
    else:
        # Single IP scan
        if not validate_ip(target_ip):
            print_status("Invalid IP address format", "error")
            return
        
        scan_single_ip(target_ip, args)

def scan_single_ip(ip, args):
    """Perform a complete scan on a single IP address"""
    start_time = time.time()
    
    # Manual Search URLs
    print_search_urls(ip)
    
    # Detailed Google Dorking Suggestions
    google_dork_search(ip)
    
    # Public IP Info
    check_ipinfo(ip)
    
    # Port Scan
    open_ports = check_ports(ip, timeout=args.timeout)
    
    if open_ports:
        # Check if it's a camera
        camera_found, evidence = check_if_camera(ip, open_ports, timeout=args.timeout)
        
        if not camera_found:
            choice = input(f"\n{Y}[❓] No camera found. Do you still want to check login pages, vulnerabilities, and passwords? [y/N]: {W}").strip().lower()
            if choice != "y":
                print_status("Scan Completed! No camera found.", "success")
                print(f"\n{G}Scan completed in {time.time() - start_time:.2f} seconds{W}")
                return
        
        # Check for login pages
        check_login_pages(ip, open_ports, timeout=args.timeout)
        
        # Check for RTSP streams
        check_rtsp_streams(ip)
        
        # Check for ONVIF support
        check_onvif_discovery(ip, timeout=args.timeout)
        
        # Fingerprint Camera Type
        if not args.no_vuln_check:
            check_camera_firmware(ip, open_ports, timeout=args.timeout)
        
        # Test Default Credentials
        if not args.no_password_check:
            test_default_passwords(ip, open_ports, timeout=args.timeout)
    
    else:
        print_status("No open ports found. Likely no camera here.", "warning")
    
    print(f"\n{G}Scan completed in {time.time() - start_time:.2f} seconds{W}")
    print_status("Scan Completed!", "success")

if __name__ == "__main__":
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print_status("Scan interrupted by user", "warning")
        sys.exit(0)
    except Exception as e:
        print_status(f"An error occurred: {str(e)}", "error")
        sys.exit(1)