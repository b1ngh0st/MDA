# Self-Guided Malware Development Syllabus
*A free, project-based curriculum based on the Malware Development Academy outline*

## Philosophy
This syllabus is structured around the "See One, Do One, Teach One" model. For each technique, you will:
1.  **Learn It:** Study the theory and existing implementations.
2.  **Build It:** Create your own implementation from scratch or by heavily modifying existing code.
3.  **Prove It:** Demonstrate mastery through a functional project and a clear explanation of how it works.

## Environment Setup
**Mandatory Lab Setup:**
*   **Host Machine:** Your regular OS (Windows, Linux, or macOS).
*   **Hypervisor:** VMware Workstation Player or VirtualBox (both free).
*   **Attacker VM:** Flare-VM (A Windows security distribution) OR a Linux VM with Mingw-w64 for cross-compilation.
*   **Target VM:** A clean Windows 10/11 VM. Use snapshots to revert to a clean state after each project.
*   **Tools:** Visual Studio Code, GCC/Mingw-w64, NASM, Objdump, Process Hacker, x64dbg.

---

## Phase 0: Foundations (Weeks 1-4)
*Master the language and the environment. This phase is non-negotiable.*

### Module 0.1: The C Programming Language
*   **Objective:** Become proficient in C, especially pointers, memory management, and structs.
*   **Resources:**
    *   "The C Programming Language" (K&R Book)
    *   [Learn C](https://www.learn-c.org/)
*   **Project:**
    1.  Write a program that implements a custom linked list and a bubble sort algorithm.
    2.  Write a program that reads a file into a buffer, modifies the bytes, and writes it back out.

### Module 0.2: Windows Internals & WinAPI
*   **Objective:** Understand core Windows concepts and how to interact with them programmatically.
*   **Resources:**
    *   [Microsoft Docs (WinAPI)](https://docs.microsoft.com/en-us/windows/win32/api/)
    *   [Ired.team - Windows Internals](https://www.ired.team/)
*   **Lessons:**
    *   Processes, Threads, Tokens, Handles, Virtual Memory.
    *   Using `CreateProcess`, `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`.
*   **Project:** Write a program that:
    1.  Starts a notepad process in a suspended state.
    2.  Allocates memory in the remote process.
    3.  Writes the string "Hello from remote process!" into the allocated memory.
    4.  Creates a remote thread that executes `MessageBoxA` to display the written string.

---

## Phase 1: Core Techniques & Basic Evasion (Weeks 5-12)

### Module 1.1: PE File Format & Shellcoding
*   **Objective:** Understand the structure of PE files and how to create position-independent code (shellcode).
*   **Resources:**
    *   [Corkami's PE101 Visual Guide](https://github.com/corkami/pics/blob/master/binary/pe101/pe101.pdf)
    *   [Ired.team - PE File Parsing](https://www.ired.team/miscellaneous-reversing-forensics/pe-file-header-parser-in-c++)
*   **Lessons:** DOS Header, NT Headers, Sections, Imports, Exports.
*   **Project:**
    1.  Write a C program that parses its own PE headers and prints its ImageBase and AddressOfEntryPoint.
    2.  Write a simple C program that launches `calc.exe`. Compile it and extract the `.text` section to use as shellcode in a later module.

### Module 1.2: Process Injection
*   **Objective:** Implement classic process injection techniques.
*   **Resources:**
    *   [Ired.team - Process Injection](https://www.ired.team/offensive-security/code-injection-process-injection)
*   **Lessons & Projects:**
    *   **Local APC Injection:** Inject shellcode into a thread within the same process.
    *   **Remote APC Injection:** Inject into a thread of a different process.
    *   **Classic DLL Injection:** Force a remote process to load your DLL.
    *   **Proof:** A single program that demonstrates all three techniques against a `notepad.exe` process. The payload for each should be the same: pop calc.

### Module 1.3: Introduction to EDRs & Unhooking
*   **Objective:** Understand how EDRs hook APIs and how to bypass them.
*   **Resources:**
    *   [Ired.team - EDR Hooking](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)
*   **Lessons:** Userland Hooking, the Native API (`ntdll.dll`).
*   **Project:**
    1.  Implement a simple program that finds the address of `NtAllocateVirtualMemory` in `ntdll.dll`'s memory and compares it to the address on disk to detect a hook.
    2.  Implement a basic unhooking technique by overwriting the in-memory `ntdll.dll` text section with a fresh copy from disk.

### Module 1.4: Direct Syscalls
*   **Objective:** Bypass userland hooks by calling system calls directly from your program.
*   **Resources:**
    *   [Ired.team - Syscalls](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)
*   **Lessons:** The `syscall` instruction, System Service Numbers (SSNs), generating syscall stubs.
*   **Project:** Re-implement your "Remote APC Injection" code from Module 1.2, but replace every hooked WinAPI (e.g., `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) with a direct syscall. This is a **key mastery project**.

---

## Phase 2: Intermediate Evasion & Stealth (Weeks 13-20)

### Module 2.1: Advanced Injection & Hollowing
*   **Objective:** Learn more stealthy injection methods that avoid classic API patterns.
*   **Resources:**
    *   Research blogs on "Process Hollowing" and "Module Stomping".
*   **Lessons & Projects:**
    *   **Process Hollowing:** Create a process suspended at `ntdll!RtlUserThreadStart`, unmap its memory, and replace it with your payload.
        *   **Proof:** A working implementation that hollows `svchost.exe`.
    *   **Module Stomping:** Load a legitimate DLL (e.g., `version.dll`) into a process, then overwrite its code section with your shellcode.
        *   **Proof:** An implementation that stomps a DLL in a remote process and executes your payload.

### Module 2.2: API Obfuscation & String Hashing
*   **Objective:** Remove plaintext API strings and IAT entries from your loaders.
*   **Resources:**
    *   [Ired.team - API Hashing](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)
*   **Lessons:** Dynamic resolution of APIs using `GetModuleHandle`/`GetProcAddress`, using hash values instead of string names.
*   **Project:** Rewrite your Syscall Injector from Phase 1. The code must have **no plaintext WinAPI function names**. All APIs (even `GetProcAddress` itself) must be resolved via a custom function that uses a hash-based lookup.

### Module 2.3: AMSI & ETW Bypass
*   **Objective:** Disable two key Microsoft defensive services programmatically.
*   **Resources:**
    *   [Ired.team - AMSI Bypass](https://www.ired.team/offensive-security/defense-evasion/amsi-bypass)
*   **Lessons:** How AMSI scans scripts and memory, How ETW reports events to EDRs.
*   **Project:**
    1.  Implement a classic AMSI bypass by patching `amsi.dll`'s `AmsiScanBuffer` function in memory to always return `AMSI_RESULT_CLEAN`.
    2.  Implement a patchless ETW bypass by using a direct syscall to `NtTraceEvent` or patching `EtwEventWrite`.

### Module 2.4: Shellcode Loaders & Encryption
*   **Objective:** Build a framework to securely deliver and load encrypted payloads.
*   **Resources:**
    *   [Ired.team - Shellcode Encryption](https://www.ired.team/offensive-security/defense-evasion/loading-encrypted-shellcode-from-remote-server)
*   **Lessons:** Simple encryption algorithms (XOR, RC4, AES), storing payloads in binary.
*   **Project:**
    *   **Mastery Project: The Loader:** Create a program that:
        1.  Contains an encrypted version of your shellcode (e.g., msfvenom payload).
        2.  Decrypts the shellcode in memory (never writes to disk).
        3.  Injects it into a target process using one of your advanced techniques (e.g., syscalls).
        4.  Implements at least one anti-analysis feature (e.g., API hashing, ETW/AMSI patch).

---

## Phase 3: Advanced Tradecraft & Research (Weeks 21+)

*This phase requires deep independent research. Resources are often academic papers or single blog posts.*

### Module 3.1: Credential Access
*   **Objective:** Extract credentials from the LSASS process.
*   **Resources:**
    *   [Deep Instinct - LSASS Dumps](https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before)
*   **Project:**
    *   **Proof:** Write a tool that can dump the SAM database from the filesystem. Then, research and implement a remote LSASS dumping technique using the `comsvcs.dll` `MiniDump` method.

### Module 3.2: Sleep Obfuscation & Evasion
*   **Objective:** Hide your shellcode from memory scanners during periods of inactivity.
*   **Resources:**
    *   Search for "Ekko Sleep Obfuscation GitHub" for example code.
*   **Project:** Implement the Ekko technique. Your shellcode should be encrypted in memory while "sleeping," and only decrypted when a timer queue callback executes. This demonstrates mastery of **Timer APIs** and **memory manipulation**.

### Module 3.3: Bring Your Own LOLBIN/Driver (BYOVD)
*   **Objective:** Leverage legitimate, signed code for malicious purposes.
*   **Resources:**
    *   Research "DLL Sideloading" and "BYOVD" techniques.
*   **Project:**
    1.  **LOLBIN:** Create a DLL sideloading pack for a known Windows binary (e.g., `notepad.exe` with `apisetschema.dll`).
    2.  **BYOVD (Research):** In a controlled lab, research a vulnerable driver (e.g., `gdrv.sys`). Write code that uses the driver's vulnerability to read kernel memory. **WARNING: This is highly complex and dangerous to your system stability.**

### Module 3.4: The Final Masterpiece
*   **Objective:** Synthesize all learned skills into one project.
*   **Project: "The Phantom Loader"**
    Create a loader that exemplifies mastery:
    *   **Payload:** Encrypted shellcode fetched from a remote server over HTTPS.
    *   **Execution:** Uses a stealthy injection technique (e.g., Module Stomping).
    *   **Evasion:**
        *   No plaintext strings or APIs (hashing required).
        *   Implements direct syscalls.
        *   Patches AMSI & ETW.
        *   Obfuscates memory during sleep (Ekko).
        *   Uses PPID Spoofing to appear as a child of a trusted process.
    *   **Proof:** A video demonstration and a detailed technical write-up explaining how each component works, why it's effective, and how it maps to the techniques in the syllabus.
