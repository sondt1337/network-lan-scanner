import os
def banner():
    """Display the application banner"""
    print(r"""
            _                                         
           | |                                        
 _ __   ___| |_   ___  ___ __ _ _ __  _ __   ___ _ __ 
| '_ \ / _ \ __| / __|/ __/ _` | '_ \| '_ \ / _ \ '__|
| | | |  __/ |_  \__ \ (_| (_| | | | | | | |  __/ |   
|_| |_|\___|\__| |___/\___\__,_|_| |_|_| |_|\___|_|   
                                                                                                         
    """)
    print("Developed by: sondt\n")

def main():
    while True:
        print("=== Select an option ===")
        print("1. Scan Local Network - Discover all active hosts")
        print("2. Host Scanner - Scan specific hosts (local & remote)")
        print("0. Exit")

        choice = input("Your choice: ")

        if choice == "1":
            os.system("python lan_scanner.py")

        elif choice == "2":
            target = input("Enter target (IP or domain): ")
            ports = input("Enter port range (default 1-1000): ") or "1-1000"

            args = f"-t {target} -p {ports}"

            if input("Enable verbose output? (y/n): ").lower() == "y":
                args += " -v"
            if input("Enable OS detection? (y/n): ").lower() == "y":
                args += " --os-detection"
            if input("Enable Service detection? (y/n): ").lower() == "y":
                args += " --service-detection"

            timeout = input("Set timeout (default 1.0s, Enter to skip): ")
            if timeout:
                args += f" --timeout {timeout}"

            threads = input("Set threads (default 100, Enter to skip): ")
            if threads:
                args += f" -T {threads}"

            cmd = f"python host_scanner.py {args}"
            print(f"Running: {cmd}")
            os.system(cmd)

        elif choice == "0":
            print("Goodbye!")
            break

        else:
            print("Invalid choice! Please select again.")

if __name__ == "__main__":
    main()
