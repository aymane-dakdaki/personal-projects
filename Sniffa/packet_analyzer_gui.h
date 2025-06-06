// Hada howa l'fichier d'en-tête lra2issi. Fih ga3 les définitions o les prototypes.
// This is the main header file. It contains all definitions and prototypes.

#ifndef PACKET_ANALYZER_GUI_H
#define PACKET_ANALYZER_GUI_H

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h> // Must be before windows.h
#include <ws2tcpip.h> // For inet_ntop, IPPROTO_*, etc.
#include <windows.h>
#include <pcap.h>     // For pcap types and functions
#include <stdio.h>    // For FILE, sprintf_s, etc.
#include <stdlib.h>   // For malloc, free, realloc, _strdup
#include <string.h>   // For strcpy_s, strcat_s, memcpy, strlen
#include <time.h>     // For time_t, struct tm, strftime
#include <stdarg.h>   // For va_list, va_start, va_end
#include <ctype.h>    // For isprint

// Common Control IDs
#define IDC_LABEL_INTERFACE 101
#define IDC_EDIT_INTERFACE  102 // This will be a ComboBox
#define IDC_LABEL_FILTER    103
#define IDC_EDIT_FILTER     104
#define IDC_BUTTON_START    105
#define IDC_BUTTON_STOP     106
#define IDC_LIST_PACKETS    107
#define IDC_EDIT_DETAILS    108

// Custom Window Message
#define WM_PACKET_DATA (WM_USER + 1)

// Structure for captured packet display info
typedef struct {
    u_char *data;
    int len;
    int caplen;
    struct pcap_pkthdr pkthdr_copy;
    char summary[256];
} CAPTURED_PACKET_DISPLAY_INFO;

// --- Logger Function Prototypes ---
int init_logger_gui(const char *filename);
void log_message_gui(const char *message);
void log_message_formatted_gui(const char *format, ...);
void close_logger_gui();

// --- Protocol Parser Function Prototypes ---
char* parse_packet_details_for_gui(const u_char *packet_data, int captured_len);
void generate_packet_summary(const u_char *packet, const struct pcap_pkthdr *pkthdr, char *summary_buf, size_t summary_buf_size);

// --- Capture Thread Function Prototypes & Structs ---
typedef struct {
    HWND hMainWnd;
    char interface_name[256];
    char filter_exp[256];
    pcap_t **pcap_handle_ptr;
    volatile BOOL *is_capturing_flag_ptr;
} CAPTURE_THREAD_PARAMS;

DWORD WINAPI CaptureThreadFunc(LPVOID lpParam); // DWORD, WINAPI, LPVOID are from windows.h
void packet_callback_gui(u_char *user_args, const struct pcap_pkthdr *pkthdr, const u_char *packet); // u_char from pcap.h

// Network constants - these should ideally come from ws2tcpip.h or pcap.h
// but define them if missing.
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

// TCP Flags - these should be defined in winsock2.h / ws2tcpip.h
// If not, your winsock headers might be old or not included correctly.
// For Npcap, these are often found in the pcap include tree (e.g. pcap/net/bpf.h or similar via pcap-stdinc.h)
// However, <winsock2.h> should provide TH_FIN, TH_SYN etc.
// It's better to rely on system headers. If these are still undeclared after fixing copy-paste,
// it points to an issue with your MinGW/Windows SDK header setup for winsock.

// The definitions for struct ether_header, ip, tcphdr, udphdr, icmphdr
// are expected to be provided by pcap.h (which includes relevant system headers)
// or directly by winsock2.h/ws2tcpip.h. Do not manually define them here
// unless absolutely necessary and guarded properly.

#endif // PACKET_ANALYZER_GUI_H