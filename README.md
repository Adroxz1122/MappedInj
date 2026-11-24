# Section-Mapping Process Injection (Windows x64)

A Windows x64 C proof of concept exploring **section-based process injection** and **thread-context redirection**. The program decrypts an embedded byte array, creates a Windows section object, maps that section into the current process and a target process, and redirects a target thread's instruction pointer to the remote mapping.

> **Status:** Experimental research code. The uploaded source contains a placeholder for the encrypted payload, so it is not a ready-to-run demonstration as provided.

## Overview

The implementation combines several Windows internals concepts:

- **AES-256-CBC decryption:** Uses the Windows Cryptography API: Next Generation (CNG) through `BCrypt*` APIs to decrypt the embedded byte array.
- **Hash-based API resolution:** Uses a DJB2-style hash to locate exported functions in a module's PE export directory.
- **PEB module enumeration:** Walks the current process' loader list to locate `ntdll.dll` without calling `GetModuleHandle` for it.
- **Section creation and mapping:** Resolves and calls `NtCreateSection` and `NtMapViewOfSection` to create a section and map views into the local and target processes.
- **Thread-context redirection:** Suspends a thread in the target process, updates its instruction pointer (`RIP`) to the remote section view, and resumes it.

## Execution flow

1. Decrypt the embedded byte array with AES-256-CBC using the configured key and IV.
2. Allocate a local buffer for the plaintext.
3. Find the target process (`notepad.exe`) and one of its threads.
4. Locate `ntdll.dll` through the PEB loader data and resolve the required native APIs by export-name hash.
5. Create a section object and map it into the current process with read/write permissions.
6. Copy the decrypted bytes into the local section view.
7. Map the same section into the target process with read/execute permissions.
8. Suspend the selected target thread, set its `RIP` to the remote mapping, and resume it.

## Requirements

- Windows x64
- A 64-bit C compiler and compatible Windows SDK (the code uses Windows headers and the x64 `GS`-register intrinsic)
- The Windows CNG library (`bcrypt.lib`)
- A target process named `notepad.exe` for the current hard-coded example
- Sufficient permissions to obtain the requested process and thread handles

## Build

From an **x64 Native Tools** command prompt for Visual Studio, a typical MSVC build command is:

```bat
cl /nologo /W4 /O2 /std:c11 mappedinjenc.c /link bcrypt.lib
```

The exact compiler and SDK versions may require adjustments to declarations for undocumented/native Windows structures and APIs.

## Payload configuration

The `shellcode_enc` array in the uploaded source is currently only a placeholder:

```c
const BYTE shellcode_enc[] = {
    // Adaptix beacon shellcode
};
```

For a meaningful test, the array must contain ciphertext produced with the same AES-256-CBC key, IV, and padding convention expected by `aes_decrypt`. The implementation uses `BCRYPT_BLOCK_PADDING`; AES-CBC ciphertext must therefore satisfy the block-size requirements and use compatible padding.

The key and IV currently present in the source are fixed demonstration values. They are not suitable for protecting real secrets. AES-CBC also does not provide authenticity or integrity checking, so successful decryption alone does not prove that the data has not been modified.

## Important limitations

This is a research PoC, not production-quality code. In its current form, it has several robustness and correctness gaps:

- `FindPID` can return an uninitialized PID when the requested process is not found.
- The code assumes that a target process and at least one target thread are available; it selects the first thread returned by the snapshot.
- Several handles and API results are not fully validated before they are used.
- Error paths do not consistently release all allocated memory, handles, or section views.
- The original thread context is not saved and restored. Redirecting `RIP` changes the selected thread's execution path.
- The implementation depends on native interfaces and loader structures that are not stable, documented application-level APIs.
- The source does not include the encrypted payload bytes, so successful execution has not been established from the uploaded file alone.

## Safety and intended use

This repository is intended for **Windows internals study, controlled lab experiments, and defensive security research**. Run it only in an isolated test environment against processes and systems you own or are explicitly authorized to assess. Do not use it to execute payloads on third-party systems.

## Learning topics

- Windows section objects and mapped views
- PE headers and export tables
- PEB and loader data structures
- Windows CNG and AES-CBC
- Native API resolution
- Thread suspension and `CONTEXT` manipulation

