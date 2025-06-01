// Hada howa lprogram lra2issi dyal l'interface graphique. Kaykhedem les deux fichiers lakhrin.
// This is the main program for the graphical interface. It uses the other two files.

#include "packet_analyzer_gui.h" // Includes all necessary headers and prototypes
#include <windowsx.h> // For GET_WM_COMMAND_ID, ListBox_*, ComboBox_* etc.
#include <commctrl.h> // For InitCommonControlsEx

// Global variables for GUI elements and state
// Les variables globales dyal les éléments d GUI o l'état
HINSTANCE hInst_main;
HWND hEditInterface_main, hEditFilter_main, hButtonStart_main, hButtonStop_main, hListPackets_main, hEditDetails_main;

pcap_t *pcap_handle_global_main = NULL;
HANDLE hCaptureThread_main = NULL;
volatile BOOL bIsCapturing_main = FALSE;
CAPTURE_THREAD_PARAMS thread_params_main;

// Dynamic array for storing captured packet display info pointers
CAPTURED_PACKET_DISPLAY_INFO **g_CapturedPackets_main = NULL;
int g_CapturedPacketsCount_main = 0;
int g_CapturedPacketsCapacity_main = 0;
#define INITIAL_PACKET_CAPACITY_MAIN 100
#define PACKET_CAPACITY_INCREMENT_MAIN 100

// Forward declarations for functions in this file
// Déclarations dyal les fonctions li kaynin f had lfile
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateGuiControls_main(HWND hwnd);
void StartCapture_main(HWND hwnd);
void StopCapture_main(HWND hwnd);
void AddPacketToGuiList_main(HWND hwnd, CAPTURED_PACKET_DISPLAY_INFO *packet_info);
void DisplayPacketDetails_main(HWND hwnd, int selected_listbox_index);
void ClearCapturedPackets_main();
void FindPcapDevices_main(HWND hCombo);
void FreeComboBoxDeviceNames(HWND hCombo);


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst_main = hInstance;
    WNDCLASSEX wcex;
    HWND hwnd;
    MSG msg;

    if (init_logger_gui("gui_network_log_main.txt") != 0) {
        MessageBox(NULL, "Failed to initialize logger. Check permissions or disk space.", "Logger Error", MB_OK | MB_ICONERROR);
    }
    log_message_gui("INFO: Application starting.");

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES | ICC_COOL_CLASSES; // Cool for ComboBoxEx if used, Win95 for basic
    InitCommonControlsEx(&icex);

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = "PacketAnalyzerWindowClassMain";
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        MessageBox(NULL, "Window Registration Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        log_message_gui("FATAL: Window class registration failed.");
        return 0;
    }

    hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE, "PacketAnalyzerWindowClassMain", "Packet Analyzer GUI (3-File)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 820, 620,
        NULL, NULL, hInstance, NULL);

    if (hwnd == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        log_message_gui("FATAL: Window creation failed.");
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    StopCapture_main(hwnd); 
    ClearCapturedPackets_main(); 
    FreeComboBoxDeviceNames(hEditInterface_main); // Clean up ComboBox item data
    log_message_gui("INFO: Application exiting.");
    close_logger_gui();
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            CreateGuiControls_main(hwnd);
            g_CapturedPacketsCapacity_main = INITIAL_PACKET_CAPACITY_MAIN;
            g_CapturedPackets_main = (CAPTURED_PACKET_DISPLAY_INFO **)malloc(sizeof(CAPTURED_PACKET_DISPLAY_INFO *) * g_CapturedPacketsCapacity_main);
            if (!g_CapturedPackets_main) {
                 MessageBox(hwnd, "Failed to allocate memory for packet storage.", "Memory Error", MB_OK | MB_ICONERROR);
                 PostQuitMessage(1);
            }
            g_CapturedPacketsCount_main = 0;
            FindPcapDevices_main(hEditInterface_main);
            break;

        case WM_COMMAND: {
            int wmId = GET_WM_COMMAND_ID(wParam);
            int wmEvent = HIWORD(wParam);

            switch (wmId) {
                case IDC_BUTTON_START: StartCapture_main(hwnd); break;
                case IDC_BUTTON_STOP: StopCapture_main(hwnd); break;
                case IDC_LIST_PACKETS:
                    if (wmEvent == LBN_SELCHANGE) {
                        int sel_idx = ListBox_GetCurSel(hListPackets_main);
                        if (sel_idx != LB_ERR) DisplayPacketDetails_main(hwnd, sel_idx);
                    }
                    break;
                default: return DefWindowProc(hwnd, message, wParam, lParam);
            }
        }
        break;

        case WM_PACKET_DATA: {
            CAPTURED_PACKET_DISPLAY_INFO *p_info = (CAPTURED_PACKET_DISPLAY_INFO *)lParam;
            if (p_info) AddPacketToGuiList_main(hwnd, p_info);
        }
        break;
        
        case WM_CLOSE:
            if (bIsCapturing_main) {
                if (MessageBox(hwnd, "Capture is running. Stop and exit?", "Confirm Exit", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    StopCapture_main(hwnd);
                    DestroyWindow(hwnd);
                }
            } else {
                DestroyWindow(hwnd);
            }
            break;

        case WM_DESTROY:
            StopCapture_main(hwnd); 
            ClearCapturedPackets_main();
            FreeComboBoxDeviceNames(hEditInterface_main);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

void CreateGuiControls_main(HWND hwnd) {
    HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, // ANSI_CHARSET or DEFAULT_CHARSET
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"); // FF_SWISS or FF_DONTCARE
    if (hFont == NULL) hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    CreateWindowEx(0, "STATIC", "Interface:", WS_CHILD | WS_VISIBLE,
                   10, 15, 80, 20, hwnd, (HMENU)IDC_LABEL_INTERFACE, hInst_main, NULL);
    hEditInterface_main = CreateWindowEx(WS_EX_CLIENTEDGE, "COMBOBOX", "",
                                    CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP,
                                    100, 12, 250, 150, hwnd, (HMENU)IDC_EDIT_INTERFACE, hInst_main, NULL);

    CreateWindowEx(0, "STATIC", "Filter:", WS_CHILD | WS_VISIBLE,
                   370, 15, 50, 20, hwnd, (HMENU)IDC_LABEL_FILTER, hInst_main, NULL);
    hEditFilter_main = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP,
                                 430, 12, 200, 24, hwnd, (HMENU)IDC_EDIT_FILTER, hInst_main, NULL);

    hButtonStart_main = CreateWindowEx(0, "BUTTON", "Start", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                                  650, 10, 70, 28, hwnd, (HMENU)IDC_BUTTON_START, hInst_main, NULL);
    hButtonStop_main = CreateWindowEx(0, "BUTTON", "Stop", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED | WS_TABSTOP,
                                 730, 10, 70, 28, hwnd, (HMENU)IDC_BUTTON_STOP, hInst_main, NULL);

    hListPackets_main = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", "",
                                  LBS_NOTIFY | WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | LBS_HASSTRINGS | WS_TABSTOP,
                                  10, 50, 780, 220, hwnd, (HMENU)IDC_LIST_PACKETS, hInst_main, NULL);

    hEditDetails_main = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
                                  WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | WS_BORDER,
                                  10, 280, 780, 280, hwnd, (HMENU)IDC_EDIT_DETAILS, hInst_main, NULL);
    
    SendMessage(hEditInterface_main, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hEditFilter_main, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hButtonStart_main, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hButtonStop_main, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hListPackets_main, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hEditDetails_main, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(GetDlgItem(hwnd, IDC_LABEL_INTERFACE), WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(GetDlgItem(hwnd, IDC_LABEL_FILTER), WM_SETFONT, (WPARAM)hFont, TRUE);
}

void FindPcapDevices_main(HWND hCombo) {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    ComboBox_ResetContent(hCombo); 
    FreeComboBoxDeviceNames(hCombo); // Free old names if any (though ResetContent should clear item data pointers too)


    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        MessageBox(NULL, errbuf, "Error Finding Devices", MB_OK | MB_ICONERROR);
        log_message_formatted_gui("ERROR: pcap_findalldevs: %s", errbuf);
        return;
    }

    for (d = alldevs; d; d = d->next) {
        char display_name[512];
        if (d->description && strlen(d->description) > 0) {
            sprintf_s(display_name, sizeof(display_name), "%s (%s)", d->description, d->name);
        } else {
            sprintf_s(display_name, sizeof(display_name), "%s (No description)", d->name);
        }
        LRESULT idx = ComboBox_AddString(hCombo, display_name);
        if (idx != CB_ERR && idx != CB_ERRSPACE) {
            char* dev_name_copy = _strdup(d->name); 
            if (dev_name_copy) {
                 ComboBox_SetItemData(hCombo, idx, (LPARAM)dev_name_copy);
            } else {
                log_message_gui("ERROR: _strdup failed for device name.");
            }
        }
    }
    if (ComboBox_GetCount(hCombo) > 0) {
        ComboBox_SetCurSel(hCombo, 0); 
    }
    pcap_freealldevs(alldevs);
}

void FreeComboBoxDeviceNames(HWND hCombo) {
    int count = ComboBox_GetCount(hCombo);
    for (int i = 0; i < count; ++i) {
        char* dev_name_copy = (char*)ComboBox_GetItemData(hCombo, i);
        if (dev_name_copy && dev_name_copy != (char*)CB_ERR) { // Check against CB_ERR as item data might be that
            free(dev_name_copy);
            // ComboBox_SetItemData(hCombo, i, (LPARAM)NULL); // Optionally clear the data pointer
        }
    }
}


void StartCapture_main(HWND hwnd) {
    if (bIsCapturing_main) return;

    ClearCapturedPackets_main(); 
    ListBox_ResetContent(hListPackets_main);
    Edit_SetText(hEditDetails_main, "");

    int selectedDevIdx = ComboBox_GetCurSel(hEditInterface_main);
    if (selectedDevIdx == CB_ERR) {
        MessageBox(hwnd, "Please select a network interface.", "Interface Error", MB_OK | MB_ICONWARNING);
        return;
    }
    char* selected_dev_name = (char*)ComboBox_GetItemData(hEditInterface_main, selectedDevIdx);
    if (!selected_dev_name || selected_dev_name == (char*)CB_ERR) { // Check against CB_ERR
         MessageBox(hwnd, "Could not retrieve interface name.", "Interface Error", MB_OK | MB_ICONERROR);
        return;
    }
    strcpy_s(thread_params_main.interface_name, sizeof(thread_params_main.interface_name), selected_dev_name);

    Edit_GetText(hEditFilter_main, thread_params_main.filter_exp, sizeof(thread_params_main.filter_exp));
    thread_params_main.hMainWnd = hwnd;
    thread_params_main.pcap_handle_ptr = &pcap_handle_global_main;
    thread_params_main.is_capturing_flag_ptr = &bIsCapturing_main;

    bIsCapturing_main = TRUE; 
    hCaptureThread_main = CreateThread(NULL, 0, CaptureThreadFunc, &thread_params_main, 0, NULL);

    if (hCaptureThread_main == NULL) {
        MessageBox(hwnd, "Failed to create capture thread.", "Thread Error", MB_OK | MB_ICONERROR);
        log_message_gui("ERROR: Failed to create capture thread.");
        bIsCapturing_main = FALSE;
        return;
    }

    EnableWindow(hButtonStart_main, FALSE);
    EnableWindow(hEditInterface_main, FALSE);
    EnableWindow(hEditFilter_main, FALSE);
    EnableWindow(hButtonStop_main, TRUE);
    log_message_gui("INFO: Capture started.");
}

void StopCapture_main(HWND hwnd) {
    if (!bIsCapturing_main && hCaptureThread_main == NULL) return;

    log_message_gui("INFO: Attempting to stop capture...");
    bIsCapturing_main = FALSE; 

    if (pcap_handle_global_main) {
        pcap_breakloop(pcap_handle_global_main); 
    }

    if (hCaptureThread_main != NULL) {
        if (WaitForSingleObject(hCaptureThread_main, 5000) == WAIT_TIMEOUT) {
            log_message_gui("WARNING: Capture thread did not terminate gracefully, forcing termination.");
            TerminateThread(hCaptureThread_main, 0); 
        }
        CloseHandle(hCaptureThread_main);
        hCaptureThread_main = NULL;
    }
    
    if (pcap_handle_global_main) {
        pcap_close(pcap_handle_global_main); 
        pcap_handle_global_main = NULL;
    }

    EnableWindow(hButtonStart_main, TRUE);
    EnableWindow(hEditInterface_main, TRUE);
    EnableWindow(hEditFilter_main, TRUE);
    EnableWindow(hButtonStop_main, FALSE);
    log_message_gui("INFO: Capture stopped.");
}

void AddPacketToGuiList_main(HWND hwnd, CAPTURED_PACKET_DISPLAY_INFO *packet_info) {
    if (!packet_info) return;

    if (g_CapturedPacketsCount_main >= g_CapturedPacketsCapacity_main) {
        g_CapturedPacketsCapacity_main += PACKET_CAPACITY_INCREMENT_MAIN;
        CAPTURED_PACKET_DISPLAY_INFO **new_storage = (CAPTURED_PACKET_DISPLAY_INFO **)realloc(g_CapturedPackets_main, sizeof(CAPTURED_PACKET_DISPLAY_INFO *) * g_CapturedPacketsCapacity_main);
        if (!new_storage) {
            log_message_gui("ERROR: Failed to realloc memory for packet storage.");
            free(packet_info->data); free(packet_info);
            return;
        }
        g_CapturedPackets_main = new_storage;
    }
    // Store the pointer to packet_info at the current count index
    g_CapturedPackets_main[g_CapturedPacketsCount_main] = packet_info;

    LRESULT index = ListBox_AddString(hListPackets_main, packet_info->summary);
    if (index != LB_ERR && index != LB_ERRSPACE) {
        // Store the index within g_CapturedPackets_main as item data for the listbox item
        ListBox_SetItemData(hListPackets_main, index, (LPARAM)g_CapturedPacketsCount_main);
    } else {
        log_message_gui("ERROR: Failed to add packet summary to ListBox.");
        // If ListBox_AddString fails, the packet_info is in g_CapturedPackets_main but not in list.
        // For simplicity, we don't remove it from g_CapturedPackets_main here, but this means
        // g_CapturedPacketsCount_main will still be incremented.
        // A more robust solution might try to remove it or handle ListBox full errors.
    }
    g_CapturedPacketsCount_main++; // Increment count *after* storing and adding to listbox
}

void DisplayPacketDetails_main(HWND hwnd, int selected_listbox_index) {
    LPARAM item_data_lparam = ListBox_GetItemData(hListPackets_main, selected_listbox_index);
    if (item_data_lparam == LB_ERR ) {
         log_message_formatted_gui("ERROR: Invalid item data (LB_ERR) from ListBox index %d.", selected_listbox_index);
         Edit_SetText(hEditDetails_main, "Error: Could not retrieve packet data for this selection (LB_ERR).");
         return;
    }
    int packet_db_index = (int)item_data_lparam; // Cast LPARAM to int, this is the index in g_CapturedPackets_main

    if (packet_db_index < 0 || packet_db_index >= g_CapturedPacketsCount_main) {
         log_message_formatted_gui("ERROR: Out-of-bounds packet_db_index %d from ListBox (count: %d).", packet_db_index, g_CapturedPacketsCount_main);
         Edit_SetText(hEditDetails_main, "Error: Could not retrieve packet data for this selection (index out of bounds).");
         return;
    }
    
    CAPTURED_PACKET_DISPLAY_INFO *packet_info = g_CapturedPackets_main[packet_db_index];

    if (packet_info && packet_info->data) {
        char *details_str = parse_packet_details_for_gui(packet_info->data, packet_info->caplen);
        if (details_str) {
            Edit_SetText(hEditDetails_main, details_str);
            free(details_str); 
        } else {
            Edit_SetText(hEditDetails_main, "Error parsing packet details or out of memory.");
            log_message_gui("ERROR: parse_packet_details_for_gui returned NULL.");
        }
    } else {
        Edit_SetText(hEditDetails_main, "No data available for this packet in our storage.");
        log_message_formatted_gui("WARNING: No packet_info or data for g_CapturedPackets_main index %d.", packet_db_index);
    }
}

void ClearCapturedPackets_main() {
    if (g_CapturedPackets_main) {
        for (int i = 0; i < g_CapturedPacketsCount_main; ++i) {
            if (g_CapturedPackets_main[i]) {
                if (g_CapturedPackets_main[i]->data) free(g_CapturedPackets_main[i]->data);
                free(g_CapturedPackets_main[i]);
            }
        }
        free(g_CapturedPackets_main); 
        g_CapturedPackets_main = NULL;
    }
    g_CapturedPacketsCount_main = 0;
    g_CapturedPacketsCapacity_main = 0; // Reset capacity for next capture session
    
    // Re-initialize for next capture, if desired, or do it in StartCapture
    g_CapturedPacketsCapacity_main = INITIAL_PACKET_CAPACITY_MAIN;
    g_CapturedPackets_main = (CAPTURED_PACKET_DISPLAY_INFO **)malloc(sizeof(CAPTURED_PACKET_DISPLAY_INFO *) * g_CapturedPacketsCapacity_main);
    if (!g_CapturedPackets_main) {
        log_message_gui("CRITICAL: Failed to re-allocate initial packet storage after clearing.");
        // This is a critical error, might need to disable capture or exit.
    }


    ListBox_ResetContent(hListPackets_main);
    Edit_SetText(hEditDetails_main, "");
    log_message_gui("INFO: Cleared all captured packet data.");
}