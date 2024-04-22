#![feature(const_maybe_uninit_zeroed, naked_functions)]
use std::mem::{transmute, MaybeUninit};
use std::{thread, time, ptr};
use nix::sys::signal;
use libc::*;

mod bindings {
    #![allow(warnings)]

    // Grab our generated bindings
    include!(concat!(env!("OUT_DIR"), "/ffi_bindings.rs"));
}

pub use bindings::{jmp_buf, sigjmp_buf, setjmp, longjmp, __sigsetjmp as sigsetjmp, siglongjmp};

const PAGE_SIZE: usize = 0x1000;

/// Stack of the running pthread
static mut stack_addr: *mut u8 = 0 as *mut u8;
static mut stack_size: usize = 0;

/// Snapshot of stack contents
static mut snap_stack: *const u8 = 0 as *const u8;

/// Snapshot of CPU context
static mut snap_context: MaybeUninit<sigjmp_buf> = MaybeUninit::<sigjmp_buf>::zeroed();

/// Stack we pivot to prior to resetting stack state
static mut alternate_stack: *mut c_void = 0 as _;
const alternate_stack_size: usize = PAGE_SIZE*16;


#[no_mangle]
unsafe fn restore() -> ! {
    println!("Restoring!");

    let mut stack_slice = std::slice::from_raw_parts_mut(stack_addr, stack_size);
    let mut snap_slice = std::slice::from_raw_parts(snap_stack, stack_size);

    stack_slice.copy_from_slice(snap_slice);
    siglongjmp(snap_context.as_mut_ptr() as _, 1);
    unreachable!();
}


// Pivot the stack during restore so we can rewrite our old stack
#[naked]
unsafe extern "sysv64" fn restore_tramp(temp_stack: usize) -> ! {
    std::arch::asm!(
        r#"
        mov rsp, rdi
        mov rbp, rsp
        jmp {RESTORE}
        "#,
        RESTORE = sym restore,
        options(noreturn),
    );
}


#[no_mangle]
extern "C" fn handle_address_fault(signum: libc::c_int, 
                                   siginfo: *mut libc::siginfo_t,
                                   context: *mut libc::c_void) {
    unsafe {
        let addr = (*siginfo).si_addr() as usize;
        println!("Got address fault at: {:#x?}", addr);
        if addr < stack_addr as usize || addr > (stack_addr as usize + stack_size) {
            panic!("Fault outside of acceptable range!");

        } else {
            unimplemented!();
        }
    };
}


#[no_mangle]
pub unsafe fn setup_signal_stack() {
    let mut s_stack = MaybeUninit::<libc::stack_t>::zeroed();

    let ss_stack_size = alternate_stack_size;
    let ss_stack_ptr = libc::mmap(ptr::null_mut(), ss_stack_size, 
                               libc::PROT_WRITE | libc::PROT_READ, 
                               libc::MAP_ANON | libc::MAP_PRIVATE, 
                               -1, 0);


    println!("Signal Stack: {:#x?}, size: {:#x?}", ss_stack_ptr, alternate_stack_size);

    (*s_stack.as_mut_ptr()).ss_flags = libc::SS_ONSTACK;
    (*s_stack.as_mut_ptr()).ss_sp = ss_stack_ptr;
    (*s_stack.as_mut_ptr()).ss_size = ss_stack_size;

    // Set the signal stack
    let ret = libc::sigaltstack(s_stack.as_ptr(), ptr::null_mut());
    if ret != 0 {
        println!("Signal stack returned: {}", ret);
        let error = *libc::__errno_location();
        println!("Error: {:?}", error);
        match error {
           libc::EFAULT => println!("Either ss or old_ss is not NULL and points to an area
                  outside of the process's address space."),

           libc::EINVAL => println!("ss is not NULL and the ss_flags field contains an invalid
                  flag."),

           libc::ENOMEM => println!("The specified size of the new alternate signal stack
                  ss.ss_size was less than MINSIGSTKSZ: {:#x}", libc::MINSIGSTKSZ),

           libc::EPERM => println!(" An attempt was made to change the alternate signal stack
                  while it was active (i.e., the thread was already
                  executing on the current alternate signal stack)."),
            _ => unimplemented!(),
        }

        println!("{:#x?}", *(s_stack.as_ptr()));
        panic!();
    }
}

#[no_mangle]
pub unsafe fn install_sigaction_libc() {
    let mut s_action = MaybeUninit::<libc::sigaction>::zeroed();
    (*s_action.as_mut_ptr()).sa_sigaction = handle_address_fault as usize;
    (*s_action.as_mut_ptr()).sa_flags = libc::SA_ONSTACK | libc::SA_SIGINFO | libc::SA_NODEFER;

    libc::sigemptyset(std::ptr::addr_of_mut!((*s_action.as_mut_ptr()).sa_mask));

    println!("{:#x?}", *s_action.as_ptr());

    let ret = libc::sigaction(libc::SIGSEGV, s_action.as_ptr(), std::ptr::null_mut());
    if ret != 0 {
        println!("Sigaction returned: {}", ret);
        panic!();
    }
}


#[no_mangle]
pub unsafe fn install_sigaction_nix() {
    let handler = signal::SigHandler::SigAction(handle_address_fault);
    let mut sigmask = signal::SigSet::empty();
    let mut flags = signal::SaFlags::SA_ONSTACK | signal::SaFlags::SA_NODEFER;
    let fault_handler = signal::SigAction::new(handler, flags, sigmask);
    signal::sigaction(signal::Signal::SIGSEGV, &fault_handler);
}

#[no_mangle]
pub unsafe fn install_thread_fault_handler() {
    setup_signal_stack();
    install_sigaction_libc();
    // install_sigaction_nix();
}



#[no_mangle]
unsafe fn snapshot() -> i32 {
    println!("Taking snapshot!");
    let stack_slice = std::slice::from_raw_parts(stack_addr, stack_size);




    let mut snap_slice = std::slice::from_raw_parts_mut(snap_stack as *mut u8, stack_size);


    snap_slice.copy_from_slice(stack_slice);

    // // This will trigger a fault like expected
    // *(0 as *mut u8) = 5;

    // mprotect the stack
    libc::mprotect(stack_addr as *mut c_void, stack_size, libc::PROT_READ);

    // This won't call the fault handler
    *(stack_addr as *mut u8) = 5;

    return sigsetjmp(snap_context.as_mut_ptr() as _, 1);
}


#[no_mangle]
unsafe fn initialize_stack_globals() {
    let mut attr = MaybeUninit::<libc::pthread_attr_t>::zeroed();

    let mut s_addr = 0 as *mut libc::c_void;
    let mut s_size = 0_usize;

    libc::pthread_getattr_np(pthread_self(), attr.as_mut_ptr());
    libc::pthread_attr_getstack(attr.as_ptr(), 
                                &mut s_addr as *mut *mut libc::c_void,   
                                &mut s_size as *mut usize);

    stack_addr = s_addr as *mut u8;
    stack_size = s_size;

    println!("pthread stack: {:#x?}", stack_addr);
    println!("pthread size:  {:#x}", stack_size);


    alternate_stack = libc::mmap(0 as *mut libc::c_void, 
                       alternate_stack_size, 
                       libc::PROT_READ | libc::PROT_WRITE, 
                       libc::MAP_ANON | libc::MAP_PRIVATE, 
                       -1, 0);


    snap_stack = libc::mmap(0 as *mut libc::c_void, 
                       stack_size, 
                       libc::PROT_READ | libc::PROT_WRITE, 
                       libc::MAP_ANON | libc::MAP_PRIVATE, 
                       -1, 0) as *const u8;

    println!("Alternate stack: {:#x?}", alternate_stack);
    println!("Stack snapshot buffer: {:#x?}", snap_stack);

}


unsafe extern "C" fn thread_loop() -> *mut libc::c_void {

    initialize_stack_globals();
    install_thread_fault_handler();

    snapshot();

    let mut k = 200;
    let mut j = 100;
    let mut i = 0;
    loop {

        if i == 8 {
            restore_tramp(alternate_stack as usize + alternate_stack_size);
        }
        
        println!("Doing work: i={}, j={}, k={}", i, j, k);
        i += 1;
        j -= 1;
        k += 100;
        thread::sleep(time::Duration::from_secs(1));
    }
}

extern "C" fn thread_entry(arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe { thread_loop() }
}

unsafe fn make_new_pthread() -> pthread_t {
    let mut thread = MaybeUninit::<pthread_t>::zeroed();
    println!("Making new thread!");

    libc::pthread_create(thread.as_mut_ptr(), 
                         std::ptr::null_mut(), 
                         thread_entry,
                         std::ptr::null_mut());

    *thread.as_ptr()
}

fn main() {
    unsafe { make_new_pthread() };
    loop {
        thread::sleep(time::Duration::from_secs(10));
    }
}
