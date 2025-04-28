import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def validate_ip(ip):
    try:
        parts = list(map(int, ip.split('.')))
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            raise ValueError
        return True
    except:
        print(f"\n[!] Invalid IP address: {ip}")
        return False

def validate_port(port):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return True
        else:
            raise ValueError
    except:
        print(f"\n[!] Invalid port: {port}")
        return False

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} is open")
                return port
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit()
    except socket.gaierror:
        print("[!] Hostname could not be resolved")
        sys.exit()
    except:
        pass

def main():
    print("\n" + "-" * 40)
    print("HACK SECURE - Basic Port Scanner")
    print("-" * 40)

    # Get user input
    ip = input("\nEnter IP address to scan: ").strip()
    if not validate_ip(ip):
        sys.exit()

    while True:
        try:
            start_port = int(input("Enter start port (1-65535): ").strip())
            end_port = int(input("Enter end port (1-65535): ").strip())
            if validate_port(start_port) and validate_port(end_port) and start_port <= end_port:
                break
            else:
                print("\n[!] Invalid port range")
        except ValueError:
            print("\n[!] Ports must be integers")

    print(f"\nScanning {ip} from port {start_port} to {end_port}...\n")

    open_ports = []
    
    # Multi-threading for faster scanning
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port+1)]
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)

    print("\n" + "-" * 40)
    if open_ports:
        print("[+] Open ports found:", sorted(open_ports))
    else:
        print("[!] No open ports found")
    print("-" * 40 + "\n")

if __name__ == "__main__":
    main()
