Packet Capture C (libpcap-compatible)

This small project demonstrates packet capture in C using a minimal libpcap-compatible API.

Files
- packet_capture.c: Example program that lists interfaces, opens one for live capture, and optionally writes captured packets to a .pcap file.
- pcap.h / pcap_stub.c: Minimal stub implementation that allows building and testing the program when libpcap/Npcap isn't available. Replace or remove these files and link against the real pcap library (wpcap) when using on Windows.

How to use

Prerequisites (recommended for Windows):
- Install Npcap (https://nmap.org/npcap/). Choose "Install Npcap in WinPcap API-compatible mode" if asked.
- Install Wireshark to open .pcap files.
- A C compiler: Visual Studio (cl.exe) or MinGW (gcc).

Build with Visual Studio Developer Command Prompt (cl):
1. Open "Developer Command Prompt for VS" (so cl and link are in PATH).
2. In the project folder (the file with packet_capture.c), run one of these:

# If using the real wpcap/npcap SDK and want to link to wpcap.lib:
cl /I. packet_capture.c /link wpcap.lib Packet.lib Ws2_32.lib Iphlpapi.lib

# To build with the local stub only (no real pcap) using cl:
cl /I. packet_capture.c ws2_32.lib

Build with MinGW (gcc):
# With real pcap (Npcap's wpcap):
# You need to have the include/lib paths for wpcap; example if using pkg-config isn't available:
gcc -I. packet_capture.c -lwpcap -lws2_32 -lIphlpapi -o packet_capture.exe

# With the local stub (no external libs):
gcc -I. packet_capture.c -o packet_capture.exe

Running
- To capture live and only print packet notifications:
  packet_capture.exe

- To capture and write to a file that Wireshark can open:
  packet_capture.exe capture_output.pcap

Notes
- On Windows you usually need Administrator privileges to capture packets. Run the command prompt as Administrator.
- When using the real Npcap/wpcap library you should remove or replace the provided `pcap.h`/`pcap_stub.c` with the SDK headers and link to `wpcap.lib` (Visual Studio) or `-lwpcap` (gcc).
- The stub (`pcap_stub.c`) simulates a few packets and provides a simple .pcap writer for testing; it does not capture real network traffic.

Opening in Wireshark
1. Start Wireshark and open the generated `capture_output.pcap` file, or double-click the file in Explorer.
2. Wireshark will display the captured packets.

If you'd like, I can:
- Add a command-line switch to select interface by name or apply a capture filter.
- Replace the stub with proper conditional compilation so the real libpcap is used automatically when available.
- Add a small PowerShell script that runs the built binary and automatically opens the resulting pcap in Wireshark.
