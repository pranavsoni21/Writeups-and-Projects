---
description: >-
  A simple, lightweight, and multi-threaded port scanner written in Python. It
  allows you to quickly check for open ports on a target host using threading
  for speed.
---

# Multithreaded Port Scanner

#### Check it out : [port-scanner.py](port-scanner.py)

#### Features

* Multi-threaded scanning for faster results
* Pretty-printed output .
* Easy to use – just run and get results
* Beginner-friendly, yet practical

***

Requirements

* Python 3.7+
* &#x20;[`tabulate`](https://pypi.org/project/tabulate/) for prettier results

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

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

***

#### Disclaimer

This tool is intended **for educational and ethical testing purposes only**.\
Do **not** use it on networks or systems you don’t own or have explicit permission to scan.
