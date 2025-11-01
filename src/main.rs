#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;

mod allocator;
mod fs;
mod gdt;
mod interrupts;
mod memory;
mod network; // Новый модуль
mod serial;
mod shell;
mod vga_buffer;

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static BootInfo) -> ! {
    use x86_64::VirtAddr;

    println!("╔══════════════════════════════════════╗");
    println!("║      PatapimOS v0.3.0 Loading...     ║");
    println!("╚══════════════════════════════════════╝");

    serial_println!("PatapimOS v0.3.0 - Boot sequence started");

    gdt::init();
    interrupts::init_idt();
    unsafe { interrupts::PICS.lock().initialize() };
    x86_64::instructions::interrupts::enable();

    println!("[OK] GDT initialized");
    println!("[OK] IDT initialized");
    println!("[OK] Interrupts enabled");
    serial_println!("[OK] Interrupt handling initialized");

    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator =
        unsafe { memory::BootInfoFrameAllocator::init(&boot_info.memory_map) };

    allocator::init_heap(&mut mapper, &mut frame_allocator).expect("Heap initialization failed");

    println!("[OK] Memory management initialized");
    println!("[OK] Heap allocator initialized");
    println!("[OK] Serial port initialized");
    println!("[OK] RAM disk initialized");

    // Инициализация сети
    match network::init_network() {
        Ok(_) => {
            println!("[OK] Network stack initialized");
            let (ip, mac) = network::get_network_info();
            println!(
                "[INFO] IP: {}, MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }
        Err(e) => {
            println!("[WARN] Network initialization failed: {}", e);
        }
    }

    serial_println!("[OK] All systems operational");
    println!();
    println!("System ready! Type 'help' for available commands.");

    shell::shell_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;

    serial_println!("KERNEL PANIC: {}", info);

    if let Some(mut writer) = vga_buffer::WRITER.try_lock() {
        write!(writer, "\n\n!!! KERNEL PANIC !!!\n{}", info).ok();
    }

    loop {
        x86_64::instructions::hlt();
    }
}
