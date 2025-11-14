#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

// Callback function called for each captured packet
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    /* header->len is an unsigned int type (bpf_u_int32) - use %u */
    printf("\n[+] Captured a packet of length %u bytes\n", (unsigned int)header->len);
    /* If a dumper is provided via 'user', write the packet to the file */
    if (user) {
        pcap_dump(user, header, packet);
    }
}

int main(int argc, char **argv) {
    WSADATA wsaData;
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_dumper_t *dumper = NULL;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[-] WSAStartup failed.\n");
        return 1;
    }

    printf("[*] Searching for network interfaces...\n");

    // Find all available network interfaces
    int res = pcap_findalldevs(&alldevs, errbuf);
    if (res == -1 || alldevs == NULL) {
        fprintf(stderr, "[-] Failed to find network devices.\nError: %s\n", errbuf);
        WSACleanup();
        return 2;
    }

    printf("[+] Available network interfaces:\n");
    int i = 0;
    for (device = alldevs; device != NULL; device = device->next) {
        printf("  [%d] %s", ++i, device->name);
        if (device->description)
            printf(" - %s", device->description);
        printf("\n");
    }

    if (i == 0) {
        printf("[-] No interfaces found. Make sure Npcap is installed and running as a service.\n");
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 0;
    }

    int choice;
    printf("\n[*] Enter the number of the interface to capture from: ");
    scanf("%d", &choice);

    if (choice < 1 || choice > i) {
        printf("[-] Invalid choice.\n");
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 0;
    }

    // Move pointer to chosen device
    device = alldevs;
    for (i = 1; i < choice; i++) device = device->next;

    printf("[*] Opening device: %s\n", device->name);

    // Open device for packet capture
    pcap_t *handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Could not open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 3;
    }

    /* If a filename was provided as the first argument, open dumper */
    if (argc > 1) {
        dumper = pcap_dump_open(handle, argv[1]);
        if (dumper == NULL) {
            fprintf(stderr, "[-] Failed to open output file: %s\n", argv[1]);
            /* proceed without dump */
        } else {
            printf("[+] Writing capture to: %s\n", argv[1]);
        }
    }

    printf("[+] Successfully opened device.\n");
    printf("[*] Capturing packets... Press Ctrl + C to stop.\n");

    // Capture packets indefinitely (Ctrl+C to break)
    pcap_loop(handle, 0, packet_handler, (u_char*)dumper);

    // Cleanup
    printf("\n[*] Cleaning up...\n");
    pcap_close(handle);
    if (dumper) pcap_dump_close(dumper);
    pcap_freealldevs(alldevs);
    WSACleanup();

    printf("[+] Capture finished.\n");
    return 0;
}
