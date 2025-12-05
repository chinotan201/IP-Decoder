# Python IP-Decoder

This is a basic IP-Decoder written in Python that captures and analyzes network packets at the IP layer using raw sockets. It extracts key information from the IP header and logs it.

## Features

- Sniffs network packets using raw sockets.
- Extracts IP header fields including version, source and destination IP addresses, protocol type, etc.
- Maps protocol numbers to human-readable protocol names (e.g., ICMP, TCP, UDP).
- Supports promiscuous mode on Windows.
- Logs packet information to a file and prints it to the console.

## Requirements

- Python 3.x
- Administrative or root privileges (for raw socket access).
- `logging` module (standard in Python).

## Usage

### Running the Sniffer

To start the sniffer, run the script from the command line:

```bash
python packet_sniffer.py <host_ip>
