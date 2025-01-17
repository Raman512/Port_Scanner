#!/bin/python3

import sys
import socket
from datetime import datetime

# Define  target
if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1])  # Translate hostname to IPv4
else:
    print("Invalid amount of arguments")
    print("syntax: python3 portscan.py <ip>")
    sys.exit()

# Add the a pretty banner
print("_" * 50)
print(f"Starting  Scan on {target}")
print(f"Time started: {str(datetime.now())}")
print("_" * 50)

# service names 
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy",
}

# Function for  grab the a banner 
def banner_grab(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        s.connect((target, port))
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")  # Basic HTTP request for banner grabbing
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner:
            return banner
    except Exception as e:
        return None
    finally:
        s.close()
    return None

# Performing  the port scan and printing the result  
try:
    for port in range(1, 65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target, port)) 
        if result == 0:
            service = services.get(port, "Unknown Service")
            banner = banner_grab(port)
            if banner:
                print(f"{target}  |  {port}/tcp  open  {service}  {banner}")
            else:
                print(f"{target}  |  {port}/tcp  open  {service}")
        s.close()

except KeyboardInterrupt:
    print("\nScan interrupted by user.")
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved.")
    sys.exit()

except socket.error:
    print("Couldn't connect to the server.")
    sys.exit()

print("_" * 50)
print(f"Scan completed at {str(datetime.now())}")
