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

If you're using Linux or macOS, running a packet sniffer may require elevated permissions. You can run the script with `sudo`:

```bash
sudo python3 SniffEx.py
```
## Usage

### Running the Sniffer

To start sniffing traffic, simply specify the network interface you want to monitor:

```bash
python3 SniffEx.py -i <interface>
```
For example:

```bash
python3 SniffEx.py -i eth0
```
### Capturing HTTP Requests

SniffEx will automatically capture HTTP requests made by devices on the network. It will display the URLs visited, along with any potential login information found within the packets.

## Example Output

<b>DEMO VIDEO </b>
 <a href="https://youtu.be/" target="_blank">
    <img src="https://raw.githubusercontent.com/maurodesouza/profile-readme-generator/master/src/assets/icons/social/youtube/default.svg" width="32" height="25" alt="youtube logo"  />
  </a>
  
  <p align="center"><img src="https://www.imghost.net/ib/0joDq3msrDs3Fhh_1727588388.png" width="50%" height="20%"/></p> 


## Customization

SniffEx allows customization to monitor specific types of traffic. You can modify the code to focus on additional layers, protocols, or extract more detailed information from the captured packets.

## Troubleshooting

If you encounter any issues, here are some common fixes:

1. **Permission Denied**: 
   - Ensure you are running the script with sufficient privileges. On Linux/macOS, use `sudo` to run the script:
     ```bash
     sudo python3 SniffEx.py
     ```

2. **No Traffic Captured**: 
   - Make sure you are monitoring the correct network interface. You can list the available interfaces using the following command (Linux/macOS):
     ```bash
     ifconfig
     ```
     For Windows, you can use:
     ```bash
     ipconfig
     ```
     Then specify the correct interface in the command:
     ```bash
     python3 SniffEx.py -i <interface>
     ```

3. **Dependencies Missing**: 
   - Verify that all required libraries are installed by running:
     ```bash
     pip install -r requirements.txt
     ```
   - If issues persist, try installing the dependencies manually:
     ```bash
     pip install scapy scapy-http
     ```

4. **No HTTP Requests Captured**: 
   - Ensure that the traffic you are capturing is HTTP-based. If the traffic is HTTPS (encrypted), SniffEx will not be able to capture the details without additional tools like SSL stripping.

## Contributing
We welcome contributions from the community! If you have ideas for improvements or new features, please follow these steps:

1. **Fork the repository**.
2. **Create a new branch** (`git checkout -b feature/YourFeature`).
3. **Make your changes** and commit them (`git commit -m 'Add some feature'`).
4. **Push your branch** (`git push origin feature/YourFeature`).
5. **Open a pull request**.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to [Scapy](https://scapy.readthedocs.io/en/latest/) for powering this tool.
- Inspired by various network scanning tools and the open-source community.
