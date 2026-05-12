# TCP Monitor

A lightweight, terminal-based TCP connection monitor for Windows, built with C# and .NET.

## Features

- **Live Connection Tracking**: View established TCP connections in real-time.
- **Traffic Monitoring**: See data sent and received by each process using Event Tracing for Windows (ETW).
- **Process Management**: Easily terminate processes or ignore them from the view.
- **Firewall Integration**: Block specific IPs easily by creating a Windows Defender Firewall rule.

## Prerequisites

- Windows OS
- .NET 8 SDK (or compatible)
- Must be run as **Administrator** (required for ETW tracking and Firewall rule creation).

## Usage

Run the compiled executable. If not running as Administrator, it will attempt to elevate itself automatically.

### Interactive Commands

*   `q`: Quit the application
*   `k`: Kill a process (interactive selection)
*   `b`: Block an IP address (creates an outbound firewall rule)
*   `i`: Ignore a process (hides it from the list)

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for more details.
