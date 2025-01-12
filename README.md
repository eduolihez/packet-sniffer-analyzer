
# Packet Sniffer Analyzer

## Description
This repository contains a Python-based packet sniffer and analyzer designed to capture and analyze network traffic. The goal of this project is to detect potential security issues such as DDoS attacks, ARP spoofing, and sensitive data (e.g., passwords) being sent over the network. It showcases my skills in network security and traffic analysis, addressing the need to monitor and secure network environments.

---

## Table of Contents
- [Packet Sniffer Analyzer](#packet-sniffer-analyzer)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Technologies Used](#technologies-used)
  - [Contributing](#contributing)
  - [License](#license)
  - [Contact](#contact)

---

## Features
- **Network Traffic Capture**: Captures packets on selected network interfaces.
- **ARP Spoofing Detection**: Alerts on potential ARP spoofing attacks.
- **DDoS Detection**: Flags possible DDoS attacks based on packet count thresholds.
- **Sensitive Data Detection**: Scans for possible sensitive data such as passwords or login information in raw packets.
- **Logging**: Logs detected attacks and important information for future analysis.

---

## Installation
Follow these steps to get a copy of the project up and running on your local machine:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/packet-sniffer-analyzer.git
   ```
2. Navigate to the project directory:
   ```bash
   cd packet-sniffer-analyzer
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the program:
   ```bash
   python sniffer.py
   ```

---

## Usage
To use this project:
1. Run the script (`sniffer.py`) after setting up the required dependencies.
2. Follow the prompts to select a network interface to sniff.
3. The program will start analyzing network packets and will alert on possible ARP spoofing, DDoS attacks, and sensitive data.

Here is an example of output from the script:

```
Packet Sniffer - Starting...
Available network interfaces:
[0] Ethernet - IP: 192.168.1.2 - MAC: 00:11:22:33:44:55 - Type: Ethernet
Select the interface number to sniff: 0
Starting packet sniffer on interface: Ethernet
[INFO] Packet: 192.168.1.100 -> 192.168.1.2
[ALERT] Possible DoS attack detected from IP: 192.168.1.100
```

---

## Technologies Used
This project was built using:
- **Scapy**: A powerful Python library used for packet capture and analysis.
- **Socket**: Used to get the local machine's IP address for excluding local traffic.
- **Colorama**: Used for colored output in the terminal.
- **Logging**: For logging detected attacks and network traffic information.

---

## Contributing
Contributions are welcome! Here’s how you can help:
1. Fork the repository.
2. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a Pull Request on GitHub.

Please make sure your contributions adhere to the [Contributor Covenant](https://www.contributor-covenant.org/).

---

## License
This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute it as you see fit. For more details, see the LICENSE file.

---

## Contact
If you have any questions or suggestions, feel free to reach out:
- **GitHub**: [eduolihez](https://github.com/eduolihez)
- **Telegram**: [your-username](t.me/eduolihez)

Thank you for checking out my project! If you found it helpful, please consider giving it a ⭐ on GitHub.
