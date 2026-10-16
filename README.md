# Dynamic API Resolution + Mapping Injection + Thread Hijacking

x64 process injection PoC combining shared-section memory mapping with thread context hijacking to execute shellcode in a remote process , resolving all Nt* functions via PEB walking and hash-based export parsing, with no calls to `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `GetProcAddress`, or `GetModuleHandle`.

Tested on Windows 10/11 x64. Uses calc.exe shellcode as a benign payload.

---

## IoCs Eliminated

| Classic Injection IoC | Replacement |
|---|---|
| `VirtualAllocEx` | `NtCreateSection` + `NtMapViewOfSection` |
| `WriteProcessMemory` | Shared memory , local view write propagates to remote |
| `CreateRemoteThread` | Thread context hijack (`SuspendThread` → `SetThreadContext` → `ResumeThread`) |
| `GetModuleHandle` | PEB walk via `__readgsqword(0x60)` |
| `GetProcAddress` | Manual PE export directory parsing with DJB2 hash matching |

No new threads are created. No memory is written across process boundaries. No Win32 resolver APIs are called.

---

## How It Works

### 1. PEB Walking , Module Resolution Without `GetModuleHandle`

```
GS:[0x60]  →  PEB
               └─ Ldr
                   └─ InMemoryOrderModuleList  (doubly-linked list of loaded modules)
                         ├─ ntdll.dll
                         ├─ kernel32.dll
                         └─ ...
```

`GetModuleHandleCustom` reads the PEB pointer directly from the thread environment block via `__readgsqword(0x60)`, walks the `InMemoryOrderModuleList`, extracts each module's filename, lowercases it, hashes it with DJB2, and returns the base address on match.

```c
PPEB pPebvar = (PEB*)(__readgsqword(0x60));
PPEB_LDR_DATA pLDR = pPebvar->Ldr;
// walk InMemoryOrderModuleList...
```

No call to `GetModuleHandleA/W` or `LoadLibrary`.

---

### 2. Export Directory Parsing , Function Resolution Without `GetProcAddress`

`GetProcAddReplacement` parses the PE export directory of the target module manually:

```
DLL base
 └─ IMAGE_DOS_HEADER  →  e_lfanew
     └─ IMAGE_NT_HEADERS
         └─ OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
             └─ IMAGE_EXPORT_DIRECTORY
                 ├─ AddressOfNames      [i]  →  function name string
                 ├─ AddressOfNameOrdinals[i] →  ordinal index
                 └─ AddressOfFunctions  [ordinal] → function RVA
```

Each exported function name is hashed with DJB2 and compared against the target hash constant. On match, the RVA is resolved to an absolute address.

No call to `GetProcAddress`. No plaintext API name strings in the binary.

---

### 3. Section-Based Injection , No `VirtualAllocEx` or `WriteProcessMemory`

```
NtCreateSection(PAGE_EXECUTE_READWRITE, SEC_COMMIT)
      │
      ├─ NtMapViewOfSection(current process, PAGE_READWRITE)   → LocalMapping
      │       memcpy(LocalMapping, shellcode, len)
      │       └─ write propagates to the shared section automatically
      │
      └─ NtMapViewOfSection(target process, PAGE_EXECUTE_READ) → RemoteMapping
```

Both views point to the same physical pages. Writing shellcode to the local `PAGE_READWRITE` view makes it readable and executable in the remote `PAGE_EXECUTE_READ` view without a single cross-process write call.

---

### 4. Thread Hijacking , No `CreateRemoteThread`

An existing thread in the target process is borrowed rather than a new one created:

```
CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)
    └─ find first thread owned by target PID  →  TID

OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)
    │
    ├─ SuspendThread
    ├─ GetThreadContext   (save current RIP and register state)
    ├─ ThreadCTX.Rip = RemoteMapping   (point RIP at shellcode)
    ├─ SetThreadContext
    └─ ResumeThread       (thread now executes shellcode on next scheduling)
```

No new thread telemetry. No `CreateRemoteThread` or `NtCreateThreadEx` call.

---

## Full Execution Flow

```
main()
  │
  ├─ FindPID("notepad.exe")         via TH32CS_SNAPPROCESS
  ├─ findTID(pid)                   via TH32CS_SNAPTHREAD
  ├─ OpenProcess(VM_OPERATION | SYNCHRONIZE | ...)
  │
  ├─ GetModuleHandleCustom(ntdll_hash)   ← PEB walk
  ├─ GetProcAddReplacement(NtCreateSection_Hash)
  ├─ GetProcAddReplacement(NtMapViewOfSection_Hash)
  │
  ├─ NtCreateSection  →  HSection
  ├─ NtMapViewOfSection(current, RW)  →  LocalMapping
  ├─ memcpy(LocalMapping, shellcode)
  ├─ NtMapViewOfSection(target, RX)   →  RemoteMapping
  │
  ├─ OpenThread  →  TargetThreadHandle
  ├─ SuspendThread
  ├─ GetThreadContext
  ├─ Rip = RemoteMapping
  ├─ SetThreadContext
  └─ ResumeThread
```

---

## Known Limitations

**RIP not preserved**
The original thread RIP is overwritten and not restored. When the shellcode executes a `RET`, control returns to whatever is on the thread's stack at the time of hijacking , likely causing the target process to crash after payload execution. A complete implementation would prepend a stub that saves the original RIP and restores it post-shellcode, or use an APC queue for safer execution.

**Section created with PAGE_EXECUTE_READWRITE**
`NtCreateSection` is called with `PAGE_EXECUTE_READWRITE`. While the individual views use minimal permissions (local RW, remote RX), the section's own protection flags are a detectable IoC. Creating the section as `PAGE_EXECUTE_READ` and mapping it locally with a separate writable view avoids this.

**First-thread assumption**
`findTID` returns the first thread found for the target PID. In practice, hijacking a thread that is currently inside a critical section or a kernel wait state can deadlock the process. A robust implementation would inspect thread state before selecting.

---

## Build

```bash
# MSVC
cl inject.c /Fe:inject.exe

# MinGW
gcc inject.c -o inject.exe -lntdll -lpsapi
```

Run with a `notepad.exe` instance already open.

---

## Detection Notes

Despite eliminating the five IoCs above, several detectable behaviors remain:

- `OpenProcess` and `OpenThread` with broad access rights generate kernel telemetry
- `NtCreateSection` with `SEC_COMMIT` + execute permissions is monitored by modern EDRs
- Thread context modification (`NtSetContextThread`) is a high-signal behavioral indicator
- `SuspendThread` on a thread in another process is flagged by many EDRs

The purpose of this project is to understand the tradeoffs in injection technique design, not to claim full EDR evasion.

---

## Related Projects

- [GhostlyIAT](https://github.com/Adroxz1122/GhostlyIAT) , the PEB walk and export directory parsing used here is an extension of techniques developed there
- [Thread-Hijacking](https://github.com/Adroxz1122/Thread-Hijacking) , standalone thread hijacking implementation

---

## References

- Windows Internals 7th Ed. , Part 1, Chapter 5 (Memory Management), Section Objects
- ReactOS source , `NtCreateSection`, `NtMapViewOfSection` signatures  
- MalDev Academy , Mapping Injection and Thread Hijacking modules
- `winternl.h`, `TlHelp32.h` , undocumented structure definitions
