# 🛡️ MyFirewall: Advanced TCP Monitor & Native Firewall

**MyFirewall** is a high-performance network security suite for Windows that combines real-time ETW (Event Tracing for Windows) network monitoring with native kernel-level traffic blocking. It provides both a modern WPF Desktop experience and a lightweight, high-speed CLI for power users.

![MyFirewall Infographic](assets/infographic.png)

## 🚀 Key Features

-   **Real-Time Monitoring:** Leverages ETW (Event Tracing for Windows) for zero-overhead, kernel-level capture of all established TCP connections.
-   **Native Firewall Integration:** Unlike many software firewalls that run in user-space, MyFirewall communicates directly with the **Windows Filtering Platform (WFP)** via the native `HNetCfg.FwPolicy2` COM API.
-   **Smart Blocking:** Instantly block suspicious remote IPs or entire application process trees.
-   **Automatic Enforce:** Detects and blocks new connection attempts from previously flagged malicious processes.
-   **Zero-Flicker UI:** Smart-diffing algorithm in the Desktop app ensures smooth, real-time updates without the "refresh flicker" common in network monitors.
-   **Geographical Insights:** Integrated Geo-IP lookup and reverse DNS to identify where your data is going.
-   **Low Resource Footprint:** Minimal CPU and RAM usage, designed for 24/7 background operation.

## 🛠 Architecture

MyFirewall is built with a focus on performance and system integrity:

-   **Kernel Tracing:** Uses `Microsoft.Diagnostics.Tracing.TraceEvent` to tap into the Windows Kernel network stack.
-   **Native Interop:** Direct COM Interop for Windows Firewall management, avoiding the overhead of `powershell.exe` or `netsh`.
-   **Process Tree Termination:** Robust process handling that cleans up entire process trees to prevent "zombie" network connections.
-   **Safe Elevation:** Built-in UAC auto-redirection to ensure the monitor has the necessary privileges to access kernel events and modify firewall policies.

## 📥 Installation & Verification

Download the latest release for your preferred environment. For security, always verify the checksums before execution.

| Asset | Platform | SHA256 Checksum |
| :--- | :--- | :--- |
| `release_cli_win_x64.zip` | Windows x64 (CLI) | `05E855F4D58D8D82AA31FCCC9E9E9A988987ED474156C154A01F9D518BCB8FF0` |
| `release_desktop_win_x64.zip` | Windows x64 (WPF) | `FA6CAE735F170EA4A654DCAAE5665C0A9EB7F8717C8B0C0C2F29C1C21C3209ED` |

### Manual Verification
```powershell
Get-FileHash MyFirewall.exe -Algorithm SHA256
```

## 📖 Usage

### Desktop App
1.  Launch `MyFirewall.Desktop.exe`.
2.  Review the live connection grid.
3.  **Right-click** any connection to block the IP, hide the application, or terminate the process tree.
4.  Monitor traffic stats and active firewall rules in the dashboard.

### CLI App
-   `Q`: Quit
-   `K`: Kill a process (interactive)
-   `B`: Block/Unblock IPs (interactive)
-   `I`: Manage ignored applications
-   `L`: Toggle detailed lists
-   `H`: Show help

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
