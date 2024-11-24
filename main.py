from scanner.network_scanner import NetworkScanner
from utils.network_utils import get_local_networks

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