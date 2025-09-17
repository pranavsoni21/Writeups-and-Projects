---
description: >-
  A simple, lightweight, and multi-threaded port scanner written in Python. It
  allows you to quickly check for open ports on a target host using threading
  for speed.
---

# Multithreaded Port Scanner

#### Check it out : [port-scanner.py](https://github.com/pranavsoni21/Writeups/blob/main/projects/port-scanner.py)

<details>

<summary>port-scanner.py</summary>

```python
#!/usr/bin/python3

import socket
import sys
from argparse import ArgumentParser
from threading import Thread
from time import time
from ipaddress import ip_address
from tabulate import tabulate

ports_open = {}


# Arguments
def arguments():
    parser = ArgumentParser(description="Multithreaded fast port scanner", usage="%(prog)s 192.168.1.1",
                            epilog="Example: %(prog)s 192.168.1.1 -p 1-5000 -t 500 -V")
    parser.add_argument(metavar="IPv4", dest="ip", help="IPv4 address to scan")
    parser.add_argument("-p", "--ports", dest="ports", help="Port range to scan", default="1-65535")
    parser.add_argument("-t", "--threads", dest="threads", help="Number of threads to use", default="500")
    parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", action="store_true")
    args = parser.parse_args()
    return args


# Validate target and Resolve hostname
def validate_ip(ip_addr):
    try:
        ip_addr = ip_address(ip_addr)
        return ip_addr
    except ValueError:
        try:
            ip_addr = socket.gethostbyname(ip_addr)
            return ip_addr
        except socket.gaierror:
            print(f"Hostname could not be resolved or Invalid IP: {ip_addr}")
            sys.exit(1)


# Getting port range
def port_range(ports_list):
    try:
        range_of_ports = []
        if "," in ports_list:
            for port in ports_list.split(","):
                port = int(port.strip())
                if 1 <= port <= 65535:
                    range_of_ports.append(port)
                else:
                    raise ValueError(f"Invalid port: {port}")

        elif "-" in ports_list:
            start, end = ports_list.split("-")
            start, end = int(start.strip()), int(end.strip())
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                range_of_ports = list(range(start, end + 1))
            else:
                raise ValueError(f"Invalid range: {start}-{end}")

        else:
            port = int(ports_list.strip())
            if 1 <= port <= 65535:
                range_of_ports.append(port)
            else:
                raise ValueError(f"Invalid port: {port}")

        return range_of_ports
    except ValueError as e:
        print(f"[!] Error while parsing ports: {e}")
        sys.exit(1)


# Port Scanning
def port_scan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((str(ip), port)) == 0:
            ports_open[port] = "Open"
            if args.verbose:
                print(f"[+] Port {port} is open")
        s.close()
    except (ConnectionRefusedError, PermissionError, OSError, socket.timeout):
        pass
    except KeyboardInterrupt:
        sys.exit()


# Preparing Threads
def prepare_threads(max_threads, ip, ports):
    thread_list = []

    for port in ports:
        t = Thread(target=port_scan, args=(ip, port))
        thread_list.append(t)

    if len(thread_list) >= int(max_threads):
        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()
        thread_list = []

    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()


if __name__ == "__main__":
    args = arguments()
    target_ip = validate_ip(args.ip)
    ports = port_range(args.ports)
    start_time = time()
    prepare_threads(args.threads, target_ip, ports)
    end_time = time()
    print(f"[+] All ports scanned successfully")
    print("\n--- Scan Results ---")
    if ports_open:
        table = [[port, status] for port, status in sorted(ports_open.items())]
        print(tabulate(table, headers=["Port", "Status"], tablefmt="fancy_grid"))
    else:
        print("No open ports found.")
    print(f"Time Taken - {round(end_time - start_time, 2)}")
```

</details>

#### Features

* Multi-threaded scanning for faster results
* Pretty-printed output .
* Easy to use – just run and get results
* Beginner-friendly, yet practical

***

Requirements

* Python 3.7+
* [`tabulate`](https://pypi.org/project/tabulate/) for prettier results

Install dependencies:

```bash
pip install tabulate
```

***

#### Usage

Run the scanner:

```bash
python3 port-scanner.py <target-host> -p <port-range> <threads>
```

Example:

```bash
python3 port-scanner.py 192.168.1.1 -p 1-10000 -t 500
```

This scans ports **1–10000** on `192.168.1.1` using **500 threads**.

```
[+] All ports scanned successfully

--- Scan Results ---
╒════════╤══════════╕
│   Port │ Status   │
╞════════╪══════════╡
│    902 │ Open     │
├────────┼──────────┤
│    912 │ Open     │
├────────┼──────────┤
│   6850 │ Open     │
├────────┼──────────┤
│   9012 │ Open     │
├────────┼──────────┤
│   9013 │ Open     │
├────────┼──────────┤
│   9014 │ Open     │
╘════════╧══════════╛
Time Taken - 4.56
```

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

***

#### Disclaimer

This tool is intended **for educational and ethical testing purposes only**.\
Do **not** use it on networks or systems you don’t own or have explicit permission to scan.
