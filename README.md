# MappedInj
x64 process injection PoC combining shared-section memory mapping with thread context hijacking to execute shellcode in a remote process — resolving all Nt* functions via PEB walking and hash-based export parsing, with no calls to VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, GetProcAddress, or GetModuleHandle.
