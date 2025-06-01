// Hada fichier fih l'implémentation dyal logger, parser, o thread d capture.
// This file contains implementations for logger, parser, and capture thread.

#include "packet_analyzer_gui.h" // Includes all necessary headers like windows.h, pcap.h, etc.

// --- Logger Implementation ---
// Implémentation dyal logger
static FILE *logfile_gui_core = NULL;

int init_logger_gui(const char *filename) {
    logfile_gui_core = fopen(filename, "a");
    if (logfile_gui_core == NULL) {
        char err_msg[256];
        sprintf_s(err_msg, sizeof(err_msg), "Error opening GUI log file: %s\n", filename);
        OutputDebugStringA(err_msg);
        return -1;
    }
    setvbuf(logfile_gui_core, NULL, _IOLBF, 0);
    log_message_gui("INFO: GUI Logger initialized.");
    return 0;
}

void log_message_gui(const char *message) {
    if (logfile_gui_core == NULL) return;
    time_t now;
    struct tm local_time_val;
    char time_buffer[26];
    time(&now);
    localtime_s(&local_time_val, &now);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &local_time_val);
    fprintf(logfile_gui_core, "[%s] %s\n", time_buffer, message);
}

void log_message_formatted_gui(const char *format, ...) {
    if (logfile_gui_core == NULL) return;
    time_t now;
    struct tm local_time_val;
    char time_buffer[26];
    char log_entry_buffer[1024];
    char user_message_buffer[800];
    time(&now);
    localtime_s(&local_time_val, &now);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &local_time_val);
    va_list args;
    va_start(args, format);
    vsnprintf_s(user_message_buffer, sizeof(user_message_buffer), _TRUNCATE, format, args);
    va_end(args);
    snprintf_s(log_entry_buffer, sizeof(log_entry_buffer), _TRUNCATE, "[%s] %s\n", time_buffer, user_message_buffer);
    fputs(log_entry_buffer, logfile_gui_core);
}

void close_logger_gui() {
    if (logfile_gui_core != NULL) {
        log_message_gui("INFO: GUI Logger shutting down.");
        fclose(logfile_gui_core);
        logfile_gui_core = NULL;
    }
}

// --- Protocol Parser Implementation ---
// Implémentation dyal parser d protocoles
#define TEMP_BUF_SIZE_CORE 2048
#define MAX_DETAIL_BUF_SIZE_CORE 8192

void safe_strcat_core(char* dest, const char* src, size_t dest_size) {
    strcat_s(dest, dest_size, src);
}

char* format_payload_gui_core(const u_char *payload, int len) {
    if (len <= 0) return _strdup(""); // Return empty string if no payload

    // Estimate buffer size: "Payload (XXX bytes):\r\n" + (len/16 lines) * ("  XXXX: (16*3 hex) (16 ascii)\r\n")
    // A line is roughly 8 (addr) + 48 (hex) + 16 (ascii) + 4 (spacing/newlines) = ~76 chars
    // So, len * 5 (hex+ascii) + 100 (header + some lines) should be generous
    size_t buffer_size = (size_t)len * 5 + 200; 
    char* buf = (char*)malloc(buffer_size);
    if (!buf) return NULL;
    
    char line_buf[256]; // For each line of payload
    sprintf_s(buf, buffer_size, "Payload (%d bytes):\r\n", len);

    for (int i = 0; i < len; i += 16) {
        char hex_part[16 * 3 + 1] = {0}; // 16 * "XX "
        char ascii_part[16 + 1] = {0};   // 16 chars + null
        
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                sprintf_s(hex_part + strlen(hex_part), sizeof(hex_part) - strlen(hex_part), "%02x ", payload[i + j]);
                ascii_part[j] = (isprint(payload[i + j])) ? payload[i + j] : '.';
            } else {
                // Pad hex part if line is not full
                strcat_s(hex_part, sizeof(hex_part), "   ");
            }
        }
        ascii_part[16] = '\0'; // Ensure null termination for ascii_part
        sprintf_s(line_buf, sizeof(line_buf), "  %04x: %-48s %s\r\n", i, hex_part, ascii_part);
        safe_strcat_core(buf, line_buf, buffer_size);
    }
    return buf;
}

char* parse_packet_details_for_gui(const u_char *packet_data, int captured_len) {
    char* full_details_buf = (char*)malloc(MAX_DETAIL_BUF_SIZE_CORE);
    if (!full_details_buf) {
        log_message_gui("ERROR: Failed to allocate memory for packet details buffer.");
        return NULL;
    }
    full_details_buf[0] = '\0';

    char temp_buf[TEMP_BUF_SIZE_CORE];
    int current_offset = 0;

    // Ethernet
    if (captured_len < sizeof(struct ether_header)) {
        sprintf_s(full_details_buf, MAX_DETAIL_BUF_SIZE_CORE, "Packet too small for Ethernet header.\r\n");
        return full_details_buf;
    }
    struct ether_header *eth_header = (struct ether_header *)packet_data;
    sprintf_s(temp_buf, sizeof(temp_buf),
              "Ethernet Header:\r\n"
              "  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\r\n"
              "  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\r\n"
              "  Type: 0x%04x\r\n\r\n",
              eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5],
              eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
              ntohs(eth_header->ether_type));
    safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
    current_offset += sizeof(struct ether_header);

    // IP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        if (captured_len < current_offset + (int)sizeof(struct ip)) { // Cast sizeof to int for comparison
             safe_strcat_core(full_details_buf, "Packet too small for IP header.\r\n", MAX_DETAIL_BUF_SIZE_CORE);
             return full_details_buf;
        }
        struct ip *ip_h = (struct ip *)(packet_data + current_offset);
        int ip_header_length = ip_h->ip_hl * 4;
         if (captured_len < current_offset + ip_header_length) {
            safe_strcat_core(full_details_buf, "Malformed IP Packet: caplen less than IP header length.\r\n", MAX_DETAIL_BUF_SIZE_CORE);
            return full_details_buf;
        }

        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_h->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_h->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

        sprintf_s(temp_buf, sizeof(temp_buf),
                  "IP Header (v%d):\r\n"
                  "  Header Length: %d bytes\r\n"
                  "  ToS: 0x%02x\r\n"
                  "  Total Length: %d\r\n"
                  "  ID: 0x%04x\r\n"
                  "  Frag Offset: %d\r\n" // Simplified, add flags later if needed
                  "  TTL: %d\r\n"
                  "  Protocol: %d\r\n"
                  "  Checksum: 0x%04x\r\n"
                  "  Src IP: %s\r\n"
                  "  Dst IP: %s\r\n\r\n",
                  ip_h->ip_v, ip_header_length, ip_h->ip_tos, ntohs(ip_h->ip_len), ntohs(ip_h->ip_id),
                  ntohs(ip_h->ip_off) & 0x1FFF, // Mask out flags for offset part
                  ip_h->ip_ttl, ip_h->ip_p, ntohs(ip_h->ip_sum), src_ip_str, dst_ip_str);
        safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
        
        const u_char *transport_packet = packet_data + current_offset + ip_header_length;
        int transport_size = captured_len - current_offset - ip_header_length;

        if (transport_size < 0) transport_size = 0; // Should not happen if previous checks pass

        switch (ip_h->ip_p) {
            case IPPROTO_TCP: {
                if (transport_size < (int)sizeof(struct tcphdr)) {
                    safe_strcat_core(full_details_buf, "Packet too small for TCP header.\r\n", MAX_DETAIL_BUF_SIZE_CORE);
                    break;
                }
                struct tcphdr *tcp_h = (struct tcphdr *)transport_packet;
                int tcp_header_len = tcp_h->th_off * 4;
                 if (transport_size < tcp_header_len) {
                    safe_strcat_core(full_details_buf, "Malformed TCP Packet: caplen less than TCP header length.\r\n", MAX_DETAIL_BUF_SIZE_CORE);
                    break;
                }
                sprintf_s(temp_buf, sizeof(temp_buf),
                          "TCP Header:\r\n"
                          "  Src Port: %d\r\n"
                          "  Dst Port: %d\r\n"
                          "  Seq Num: %u\r\n"
                          "  Ack Num: %u\r\n"
                          "  Header Length: %d bytes\r\n"
                          "  Flags: %s%s%s%s%s%s\r\n"
                          "  Window: %d\r\n"
                          "  Checksum: 0x%04x\r\n"
                          "  Urg Pointer: %d\r\n\r\n",
                          ntohs(tcp_h->th_sport), ntohs(tcp_h->th_dport),
                          ntohl(tcp_h->th_seq), ntohl(tcp_h->th_ack), tcp_header_len,
                          (tcp_h->th_flags & TH_URG) ? "U" : "-", (tcp_h->th_flags & TH_ACK) ? "A" : "-",
                          (tcp_h->th_flags & TH_PUSH) ? "P" : "-", (tcp_h->th_flags & TH_RST) ? "R" : "-",
                          (tcp_h->th_flags & TH_SYN) ? "S" : "-", (tcp_h->th_flags & TH_FIN) ? "F" : "-",
                          ntohs(tcp_h->th_win), ntohs(tcp_h->th_sum), ntohs(tcp_h->th_urp));
                safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
                if (transport_size > tcp_header_len) {
                    char* payload_str = format_payload_gui_core(transport_packet + tcp_header_len, transport_size - tcp_header_len);
                    if (payload_str) {
                        safe_strcat_core(full_details_buf, payload_str, MAX_DETAIL_BUF_SIZE_CORE);
                        free(payload_str);
                    }
                }
                break;
            }
            case IPPROTO_UDP: {
                 if (transport_size < (int)sizeof(struct udphdr)) {
                    safe_strcat_core(full_details_buf, "Packet too small for UDP header.\r\n", MAX_DETAIL_BUF_SIZE_CORE);
                    break;
                }
                struct udphdr *udp_h = (struct udphdr *)transport_packet;
                sprintf_s(temp_buf, sizeof(temp_buf),
                          "UDP Header:\r\n"
                          "  Src Port: %d\r\n"
                          "  Dst Port: %d\r\n"
                          "  Length: %d\r\n"
                          "  Checksum: 0x%04x\r\n\r\n",
                          ntohs(udp_h->uh_sport), ntohs(udp_h->uh_dport), ntohs(udp_h->uh_ulen), ntohs(udp_h->uh_sum));
                safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
                 if (transport_size > (int)sizeof(struct udphdr)) {
                    char* payload_str = format_payload_gui_core(transport_packet + sizeof(struct udphdr), transport_size - sizeof(struct udphdr));
                    if (payload_str) {
                        safe_strcat_core(full_details_buf, payload_str, MAX_DETAIL_BUF_SIZE_CORE);
                        free(payload_str);
                    }
                }
                break;
            }
            case IPPROTO_ICMP: {
                if (transport_size < (int)sizeof(struct icmphdr)) { // Basic ICMP header is 4 bytes, echo is 8
                    safe_strcat_core(full_details_buf, "Packet too small for ICMP header.\r\n", MAX_DETAIL_BUF_SIZE_CORE);
                    break;
                }
                struct icmphdr *icmp_h = (struct icmphdr *)transport_packet;
                sprintf_s(temp_buf, sizeof(temp_buf),
                          "ICMP Header:\r\n"
                          "  Type: %d\r\n"
                          "  Code: %d\r\n"
                          "  Checksum: 0x%04x\r\n",
                          icmp_h->type, icmp_h->code, ntohs(icmp_h->checksum));
                if (icmp_h->type == ICMP_ECHO || icmp_h->type == ICMP_ECHOREPLY) {
                     if (transport_size >= 8) { // Echo/Reply have ID and Seq
                        char temp_echo[100];
                        sprintf_s(temp_echo, sizeof(temp_echo), "  ID: %d\r\n  Sequence: %d\r\n", 
                                ntohs(icmp_h->un.echo.id), ntohs(icmp_h->un.echo.sequence));
                        safe_strcat_core(temp_buf, temp_echo, sizeof(temp_buf));
                    }
                }
                safe_strcat_core(temp_buf, "\r\n", sizeof(temp_buf)); // Extra newline after ICMP header
                safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
                
                int icmp_header_size = 4; // Minimum ICMP header
                if (icmp_h->type == ICMP_ECHO || icmp_h->type == ICMP_ECHOREPLY || 
                    icmp_h->type == ICMP_TIMESTAMP || icmp_h->type == ICMP_TIMESTAMPREPLY ||
                    icmp_h->type == ICMP_INFO_REQUEST || icmp_h->type == ICMP_INFO_REPLY) {
                    icmp_header_size = 8; // These types have ID and Sequence or similar
                }
                
                if (transport_size > icmp_header_size) {
                     char* payload_str = format_payload_gui_core(transport_packet + icmp_header_size, transport_size - icmp_header_size);
                    if (payload_str) {
                        safe_strcat_core(full_details_buf, payload_str, MAX_DETAIL_BUF_SIZE_CORE);
                        free(payload_str);
                    }
                }
                break;
            }
            default:
                sprintf_s(temp_buf, sizeof(temp_buf), "Other L4 Protocol: %d\r\n", ip_h->ip_p);
                safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
                // Optionally print payload for unknown IP protocols
                if (transport_size > 0) {
                    char* payload_str = format_payload_gui_core(transport_packet, transport_size);
                     if (payload_str) {
                        safe_strcat_core(full_details_buf, payload_str, MAX_DETAIL_BUF_SIZE_CORE);
                        free(payload_str);
                    }
                }
                break;
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        sprintf_s(temp_buf, sizeof(temp_buf), "ARP Protocol (Details not implemented)\r\n");
        safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        sprintf_s(temp_buf, sizeof(temp_buf), "IPv6 Protocol (Details not implemented)\r\n");
        safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
    }
    else {
        sprintf_s(temp_buf, sizeof(temp_buf), "Other L3 Protocol: 0x%04x\r\n", ntohs(eth_header->ether_type));
        safe_strcat_core(full_details_buf, temp_buf, MAX_DETAIL_BUF_SIZE_CORE);
    }
    return full_details_buf;
}

void generate_packet_summary(const u_char *packet, const struct pcap_pkthdr *pkthdr, char *summary_buf, size_t summary_buf_size) {
    char src_ip_str[INET_ADDRSTRLEN] = "N/A";
    char dst_ip_str[INET_ADDRSTRLEN] = "N/A";
    char protocol_str[20] = "Unknown"; // Increased size for "ETH 0xFFFF"
    int src_port = 0, dst_port = 0;
    int current_offset = 0;

    if (pkthdr->caplen >= sizeof(struct ether_header)) {
        struct ether_header *eth = (struct ether_header *)packet;
        current_offset += sizeof(struct ether_header);

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            if (pkthdr->caplen >= current_offset + sizeof(struct ip)) {
                struct ip *iph = (struct ip *)(packet + current_offset);
                inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
                
                int ip_hdr_len = iph->ip_hl * 4;
                current_offset += ip_hdr_len;
                const u_char *transport_layer = packet + sizeof(struct ether_header) + ip_hdr_len; // Correct offset
                int transport_len = pkthdr->caplen - (sizeof(struct ether_header) + ip_hdr_len); // Correct remaining length

                if (transport_len < 0) transport_len = 0;

                switch (iph->ip_p) {
                    case IPPROTO_TCP: 
                        strcpy_s(protocol_str, sizeof(protocol_str), "TCP");
                        if (transport_len >= (int)sizeof(struct tcphdr)) {
                            struct tcphdr *tcph = (struct tcphdr*)transport_layer;
                            src_port = ntohs(tcph->th_sport);
                            dst_port = ntohs(tcph->th_dport);
                        }
                        break;
                    case IPPROTO_UDP: 
                        strcpy_s(protocol_str, sizeof(protocol_str), "UDP");
                         if (transport_len >= (int)sizeof(struct udphdr)) {
                            struct udphdr *udph = (struct udphdr*)transport_layer;
                            src_port = ntohs(udph->uh_sport);
                            dst_port = ntohs(udph->uh_dport);
                        }
                        break;
                    case IPPROTO_ICMP: strcpy_s(protocol_str, sizeof(protocol_str), "ICMP"); break;
                    default: sprintf_s(protocol_str, sizeof(protocol_str), "IP %d", iph->ip_p); break;
                }
            } else {
                 strcpy_s(protocol_str, sizeof(protocol_str), "IP (short)");
            }
        } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
             strcpy_s(protocol_str, sizeof(protocol_str), "ARP");
        } else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) {
             strcpy_s(protocol_str, sizeof(protocol_str), "IPv6");
        }
        else {
            sprintf_s(protocol_str, sizeof(protocol_str), "ETH 0x%04x", ntohs(eth->ether_type));
        }
    } else {
        strcpy_s(protocol_str, sizeof(protocol_str), "Too Short");
    }
    
    if (src_port != 0 && dst_port != 0) { // Typically for TCP/UDP
         sprintf_s(summary_buf, summary_buf_size,
                  "%s:%d -> %s:%d %s (%d B)",
                  src_ip_str, src_port, dst_ip_str, dst_port, protocol_str, pkthdr->caplen);
    } else { // For ICMP, ARP, or IP packets without port info shown
         sprintf_s(summary_buf, summary_buf_size,
                  "%s -> %s %s (%d B)",
                  src_ip_str, dst_ip_str, protocol_str, pkthdr->caplen);
    }
}


// --- Capture Thread Implementation ---
// Implémentation dyal thread d capture
void packet_callback_gui(u_char *user_args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    CAPTURE_THREAD_PARAMS *params = (CAPTURE_THREAD_PARAMS *)user_args;
    if (!params || !*(params->is_capturing_flag_ptr)) {
        return; 
    }

    CAPTURED_PACKET_DISPLAY_INFO *packet_info = (CAPTURED_PACKET_DISPLAY_INFO *)malloc(sizeof(CAPTURED_PACKET_DISPLAY_INFO));
    if (!packet_info) {
        log_message_gui("ERROR (Callback): Failed to allocate memory for packet_info.");
        return;
    }

    packet_info->data = (u_char *)malloc(pkthdr->caplen);
    if (!packet_info->data) {
        log_message_gui("ERROR (Callback): Failed to allocate memory for packet data copy.");
        free(packet_info);
        return;
    }

    memcpy(packet_info->data, packet, pkthdr->caplen);
    packet_info->len = pkthdr->len;
    packet_info->caplen = pkthdr->caplen;
    memcpy(&packet_info->pkthdr_copy, pkthdr, sizeof(struct pcap_pkthdr));

    generate_packet_summary(packet, pkthdr, packet_info->summary, sizeof(packet_info->summary));

    if (!PostMessage(params->hMainWnd, WM_PACKET_DATA, 0, (LPARAM)packet_info)) {
        log_message_gui("ERROR (Callback): PostMessage failed.");
        free(packet_info->data);
        free(packet_info);
    }
}

DWORD WINAPI CaptureThreadFunc(LPVOID lpParam) {
    CAPTURE_THREAD_PARAMS *params = (CAPTURE_THREAD_PARAMS *)lpParam;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_local_thread; 

    log_message_formatted_gui("INFO (Thread): Starting capture on %s with filter '%s'", params->interface_name, params->filter_exp);

    handle_local_thread = pcap_open_live(params->interface_name, BUFSIZ, 1, 1000, errbuf); // promisc=1, timeout=1000ms
    if (handle_local_thread == NULL) {
        log_message_formatted_gui("ERROR (Thread): pcap_open_live failed: %s", errbuf);
        char msg_buf[PCAP_ERRBUF_SIZE + 100];
        sprintf_s(msg_buf, sizeof(msg_buf), "pcap_open_live failed for %s:\n%s", params->interface_name, errbuf);
        MessageBox(params->hMainWnd, msg_buf, "Capture Error", MB_OK | MB_ICONERROR);
        *(params->is_capturing_flag_ptr) = FALSE; 
        *(params->pcap_handle_ptr) = NULL; 
        PostMessage(params->hMainWnd, WM_COMMAND, MAKEWPARAM(IDC_BUTTON_STOP, 0), 0); 
        return 1;
    }
    *(params->pcap_handle_ptr) = handle_local_thread;

    struct bpf_program fp;
    if (pcap_compile(handle_local_thread, &fp, params->filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) { // netmask unknown for simplicity
        log_message_formatted_gui("ERROR (Thread): pcap_compile failed: %s", pcap_geterr(handle_local_thread));
        MessageBox(params->hMainWnd, pcap_geterr(handle_local_thread), "Filter Compilation Error", MB_OK | MB_ICONERROR);
        pcap_close(handle_local_thread);
        *(params->is_capturing_flag_ptr) = FALSE;
        *(params->pcap_handle_ptr) = NULL;
        PostMessage(params->hMainWnd, WM_COMMAND, MAKEWPARAM(IDC_BUTTON_STOP, 0), 0);
        return 1;
    }
    if (pcap_setfilter(handle_local_thread, &fp) == -1) {
        log_message_formatted_gui("ERROR (Thread): pcap_setfilter failed: %s", pcap_geterr(handle_local_thread));
        MessageBox(params->hMainWnd, pcap_geterr(handle_local_thread), "Set Filter Error", MB_OK | MB_ICONERROR);
        pcap_freecode(&fp);
        pcap_close(handle_local_thread);
        *(params->is_capturing_flag_ptr) = FALSE;
        *(params->pcap_handle_ptr) = NULL;
        PostMessage(params->hMainWnd, WM_COMMAND, MAKEWPARAM(IDC_BUTTON_STOP, 0), 0);
        return 1;
    }
    pcap_freecode(&fp); 

    log_message_gui("INFO (Thread): Capture loop starting...");
    pcap_loop(handle_local_thread, -1, packet_callback_gui, (u_char *)params); 
    
    log_message_gui("INFO (Thread): Capture loop ended.");
    // The handle (handle_local_thread which is pointed to by *(params->pcap_handle_ptr))
    // will be closed by the main thread's StopCapture function.
    return 0;
}