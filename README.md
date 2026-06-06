# 🛡️ MyFirewall: Advanced TCP Monitor & Native Windows Firewall

**MyFirewall** is a high-performance network security suite for Windows that integrates real-time kernel-level ETW (Event Tracing for Windows) monitoring with native traffic blocking. It provides both a modern WPF Desktop UI and a lightweight, high-speed CLI for command-line power users.

![MyFirewall Infographic](assets/infographic.png)

## 🚀 Key Features

- **Real-Time Monitoring:** Zero-overhead, kernel-level tracing of all TCP connections using Event Tracing for Windows (ETW).
- **Native WFP Integration:** Direct integration with the Windows Filtering Platform (WFP) via the COM `HNetCfg.FwPolicy2` API. Unlike standard solutions, it does not rely on calling slow `netsh.exe` or `powershell.exe` processes.
- **Threat Intelligence:** Process Metadata Service that queries execution path, parent process information, digital signature validation, and file timestamps using P/Invoke APIs.
- **Smart Rule Management:** Persistent blocked IP list (`blocked.txt`) storing timestamped metadata, with sub-millisecond late-binding evaluation via COM rules.
- **Smart-Diff WPF Layout:** Custom Wpf list diffing that prevents visual flickering when connections update in real-time.
- **Geographical & Reverse DNS lookup:** Resolves remote hostnames and locations asynchronously with automatic TTL-based caching.
- **Process Tree Termination:** Cleanly stops suspicious applications along with their entire process tree to prevent lingering connections.
- **Language Sync & Widget Management:** System utilities to inspect and toggle Windows features like widgets, search box, and setting synchronization.

---

## 🛠 Architecture

MyFirewall is designed with low overhead and strong security constraints:

```
[Network Activity] ──> [Windows Kernel (ETW)] ──> [NetworkMonitorService]
                                                           │
 [WPF Desktop UI]  <── [MainViewModel (Smart Diff)] <──────┼──> [ProcessMetadataService]
       or                                                  │    (Digital Signatures)
  [Console CLI]    <───────────────────────────────────────┘
       │
       └──> [FirewallManager (Direct COM Interop)] ──> [Windows Filtering Platform]
```

1. **Kernel Tracing:** Connects to Microsoft Windows kernel events to catch socket connection creations.
2. **Metadata Evaluation:** TTL-evicted (60s) metadata caches prevent process-identity confusion when Windows recycles PIDs.
3. **Firewall Rules:** Grouped under the `MyFirewall-` namespace, rule-evaluation occurs natively in kernel space.

---

## 📥 Installation & Verification

Download the verified release zip archives below:

| Asset | Platform | SHA256 Checksum |
| :--- | :--- | :--- |
| `release_cli_win_x64.zip` | Windows x64 (CLI Console) | `161942FBF0AAB6C6529665646CEBC310694CACE4743896281D8715D91E5F402A` |
| `release_desktop_win_x64.zip` | Windows x64 (WPF Desktop UI) | `F5ACBDB482EB0C8DB9FA72D288CF884793445713C7265EBF9FA12844B7C247DE` |

### Manual Verification
Ensure the integrity of the downloaded binaries using PowerShell:
```powershell
Get-FileHash release_desktop_win_x64.zip -Algorithm SHA256
```

---

## 📖 Usage

Both applications require administrative privileges (UAC elevation) to hook into the ETW session and communicate with the native firewall COM interface.

### Desktop WPF UI
1. Launch `MyFirewall.Desktop.exe`.
2. Inspect live connection stats, bandwidth activity, and the active connections grid.
3. **Right-Click** any row to:
   - **Block Remote IP:** Create a native block rule immediately.
   - **Ignore Process:** Filter out the application from the monitoring panel.
   - **Kill Process Tree:** Terminate the process and its subprocesses.
4. Use the toolbar toggles to choose between **Connection-Driven** or **Proactive ETW Process Start** threat intelligence monitoring strategies.

### Console CLI
Run `MyFirewall.exe`. Interact using the following keyboard controls:
- **`Q`**: Quit the monitor cleanly.
- **`K`**: Kill an active process by PID or Name (interactive).
- **`B`**: Manage blocked IPs list.
- **`I`**: Manage ignored processes list.
- **`P`**: Show Process Intelligence/Details (parent PID, path, digital signature).
- **`T`**: Toggle Threat Intelligence strategy at runtime.
- **`L`**: Toggle extra lists (active blocks and ignores) on the console view.
- **`H`**: Display help drawer.

---

## 📄 License
This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
