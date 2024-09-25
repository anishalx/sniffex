# SniffEx

## Overview

**SniffEx** is a powerful and easy-to-use packet sniffer designed to monitor and capture network traffic, focusing on HTTP requests and identifying potential login information. Whether you are a network security enthusiast, pentester, or developer, SniffEx provides a comprehensive solution for analyzing network traffic in real-time.

This project was built using Python and Scapy, making it lightweight and efficient. With simple commands, users can install, configure, and start monitoring network traffic on their devices.

---

## Features

- Real-time sniffing of network traffic.
- Extracts and displays URLs and HTTP request details.
- Identifies potential login credentials (username and password) from traffic.
- Lightweight and efficient.
- Easy setup and usage.

---

## Requirements

To run SniffEx, you will need the following:

- Python 3.x
- Scapy (`pip install scapy`)
- Scapy-HTTP (`pip install scapy-http`)

---

## Installation

### Step 1: Clone the Repository

To get started, first clone this repository to your local machine:

```bash
git clone https://github.com/anishalx/sniffex.git
cd sniffex
```
### Step 2: Install the Dependencies

Once you have cloned the repository, you need to install the required dependencies:

```bash
pip install -r requirements.txt
```

The required packages include:

- **Scapy**: For network traffic capturing and packet analysis.
- **Scapy-HTTP**: For parsing HTTP requests and responses.

### Step 3: Set Up Permissions (Linux/macOS)

If you're using Linux or macOS, running a packet sniffer may require elevated permissions. You can run the script with 'sudo':

```bash
sudo python3 SniffEx.py
```
