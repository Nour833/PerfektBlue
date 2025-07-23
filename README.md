<div align="center">
  <img src="logo.png" alt="PerfektBlue Logo" width="256" height="256">
  <h1>PerfektBlue</h1>
  <p><b>An Automotive Bluetooth & CAN Exploitation Framework</b></p>
  <p>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.x-blue.svg" alt="Python 3.x"></a>
  </p>
</div>

PerfektBlue is a framework for automotive security assessment, providing a guided, multi-stage process to probe, exploit, and interact with vehicle infotainment and control systems via Bluetooth and CAN bus.

## Attack Workflow

PerfektBlue follows a systematic methodology to assess and exploit target systems. Understanding this workflow is key to using the tool effectively.

### Stage 1: Reconnaissance & Fingerprinting

The first step is to gather intelligence about the target.

*   **Bluetooth Scan:** The tool begins by performing a Bluetooth service scan (`sdptool`) on the provided MAC address. This identifies open profiles and services. The primary goal is to find the **AVRCP (Audio/Video Remote Control Profile)** service, which is the entry point for the initial exploit.
*   **Nmap Scan (Optional):** If a target IP address is provided, `nmap` is used to perform OS and service fingerprinting. This can reveal the underlying operating system and other running services, which helps in selecting the correct shellcode architecture.

### Stage 2: Exploitation

This stage focuses on gaining initial access to the system.

1.  **AVRCP Information Leak:** PerfektBlue sends a specially crafted, malformed AVRCP command to the target. In vulnerable systems, this can cause the service to crash or respond incorrectly, leaking a small amount of memory from the stack or heap. This leaked data may contain a memory address.
2.  **Shellcode Generation:** Using the information from the fingerprinting stage, `msfvenom` is used to generate a reverse shell payload for the appropriate architecture (e.g., ARM, x86). The payload is configured to connect back to the attacker's IP address.
3.  **Heap Overflow:** The tool constructs a payload that combines a buffer of junk data, the leaked memory address (if obtained), and the `msfvenom` shellcode. This payload is sent to the target, attempting to overwrite the program's execution flow and force it to run the shellcode.

### Stage 3: Post-Exploitation

Once the shellcode is executed, this stage manages the connection.

*   **Reverse Shell Listener:** The framework starts a listener on the specified port. If the exploit was successful, the target system will connect back, providing an interactive command shell. From here, the attacker can explore the compromised system.

### Stage 4: CAN Bus Analysis

If a shell is obtained or if the vehicle's network is otherwise accessible, PerfektBlue can interact with the CAN bus.

*   **CAN Fuzzing:** Sends a stream of random CAN messages to the specified interface. This can be used to discover unexpected behavior or vulnerabilities in various Electronic Control Units (ECUs).
*   **CAN Mapping & Replay:** The tool can listen for and record CAN messages, saving them to a database. This allows for the mapping of commands (e.g., discovering the command to unlock doors). These mapped commands can then be replayed.

## Installation

For Debian-based systems like Kali Linux and Parrot OS, you can install PerfektBlue using the provided `.deb` package.

1.  **Download** the latest `perfektblue.deb` from the releases page.
2.  **Install** the package using `apt`:
    ```bash
    sudo apt update
    sudo apt install ./perfektblue.deb
    ```
    This will automatically install all required dependencies, including `metasploit-framework`.

## Usage

1.  **Launch** the application from your terminal or application menu:
    ```bash
   sudo perfektblue
    ```
2.  **Follow the on-screen prompts** to proceed through the attack workflow. The tool will guide you from fingerprinting to exploitation and beyond.

## Disclaimer

**WARNING: This tool is for security research and educational purposes only. Only use on systems you own or have explicit permission to test. The developers assume no liability for any misuse or damage caused by this software. Automotive systems are safety-critical - testing on live vehicles can be dangerous and illegal without proper authorization.**

## License

Distributed under the MIT License. See `LICENSE` for more information.
