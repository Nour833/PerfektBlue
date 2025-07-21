# PerfektBlue: Bluetooth & CAN Bus Fuzzing Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/downloads/)

PerfektBlue is an advanced security testing framework designed for discovering vulnerabilities in automotive systems through Bluetooth-enabled infotainment systems and Electronic Control Units (ECUs). This tool automates Bluetooth service fuzzing, CAN Bus communication testing, payload generation, and log analysis to help security researchers identify weaknesses in vehicle systems.

## Features

- **Bluetooth Fuzzing**: Sends mutated payloads to Bluetooth services (especially AVRCP) to discover vulnerabilities
- **CAN Bus Fuzzing**: Generates and sends random CAN frames to test vehicle networks
- **Automated Payload Generation**: Uses intelligent mutation strategies to create exploit payloads
- **Log Analysis**: Integrates with `btmon` for real-time Bluetooth traffic monitoring and crash detection
- **Interactive UI**: User-friendly interface for device selection and service scanning
- **Cross-Platform**: Designed for Linux-based systems with Bluetooth and CAN capabilities
- **Crash Detection**: Heuristic-based crash identification with automatic payload adjustment

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Prerequisites](#prerequisites)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Acknowledgements](#acknowledgements)
- [Contact](#contact)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nour833/PerfektBlue.git
   cd PerfektBlue
   ```

2. Install required dependencies:
   ```bash
   sudo apt install bluez can-utils bluetooth 
   pip install -r requirements.txt
   ```

3. Set up Bluetooth interface:
   ```bash
   sudo hciconfig hci0 up
   ```

4. For CAN Bus testing, set up virtual CAN interface:
   ```bash
   sudo modprobe vcan
   sudo ip link add dev can0 type vcan
   sudo ip link set up can0
   ```

## Usage

### Basic Execution
```bash
python3 PerfektBlue.py
```

### Interactive Bluetooth Fuzzing
1. Run the script and select Bluetooth scanning option
2. Choose target device from discovered devices
3. Service scan will detect available Bluetooth services
4. Framework will automatically select AVRCP services if available
5. Fuzzing will begin with real-time crash monitoring via `btmon`

### CAN Bus Fuzzing
1. Ensure CAN interface is configured (default: `can0`)
2. When prompted, select CAN fuzzing option
3. Framework will send randomized CAN frames to the specified interface
4. Monitor target system for anomalies during testing

### Payload Generation
The framework uses intelligent mutation strategies:
- Bit flipping
- Payload truncation
- Random byte insertion
- Length extension
- Crash-based heuristic adjustments

### Log Analysis
- `btmon` is automatically launched during Bluetooth fuzzing
- Crash patterns detected: Disconnects, Errors, Link Loss, Timeouts, Resets
- Logs are monitored in real-time with crash-triggered termination

## Prerequisites
- Linux-based OS (Debian-based: Kali linux, Ubuntu ... recommended)
- Python 3.6+
- Bluetooth 4.0+ adapter
- Root privileges for Bluetooth/CAN operations
- Hardware:
  - For Bluetooth testing: Any Linux-compatible Bluetooth dongle
  - For CAN testing: CAN interface adapter (e.g. Peak PCAN, Kvaser, or virtual CAN)

## Contributing
We welcome contributions! Please follow these steps:
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a pull request

## License
Distributed under the MIT License. See `LICENSE` for more information.

## Disclaimer
**WARNING: This tool is for security research and educational purposes only. Only use on systems you own or have explicit permission to test. The developers assume no liability for any misuse or damage caused by this software. Automotive systems are safety-critical - testing on live vehicles can be dangerous and illegal without proper authorization.**

## Acknowledgements
- BlueZ Project - Linux Bluetooth stack
- python-can - CAN bus interface library
- Linux SocketCAN subsystem
- btmon - Bluetooth monitor tool

## Contact
Project Maintainer: nour833  
GitHub Issues: [https://github.com/nour833/PerfektBlue/issues](https://github.com/nour833/PerfektBlue/issues)
