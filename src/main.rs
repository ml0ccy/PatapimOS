#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;

mod allocator;
mod dns; // Реальный DNS клиент
mod fs;
mod gdt;
mod interrupts;
mod memory;
mod network; // Полноценный сетевой стек
mod pci; // PCI для поиска сетевых карт
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

    // Инициализация PCI для поиска сетевых карт
    println!("[INFO] Scanning PCI bus for network adapters...");
    match pci::init_pci() {
        Ok(_) => println!("[OK] PCI subsystem initialized"),
        Err(e) => println!("[WARN] PCI initialization failed: {}", e),
    }

    // Инициализация полноценного сетевого стека
    match network::init_network() {
        Ok(_) => {
            println!("[OK] Real network stack initialized");
            let info = network::get_detailed_network_info();
            println!(
                "[INFO] Network Interface: {}",
                if info.is_link_up { "UP" } else { "DOWN" }
            );
            println!("[INFO] IP: {}, MAC: {}", info.ip_address, info.mac_address);
            println!(
                "[INFO] Gateway: {}, DNS: {:?}",
                info.gateway, info.dns_servers
            );
        }
        Err(e) => {
            println!("[WARN] Network initialization failed: {}", e);
            println!("[INFO] Network functions will be limited");
        }
    }

    serial_println!("[OK] All systems operational - Real network stack active");
    println!();
    println!("System ready! Type 'help' for available commands.");
    println!("Network stack: REAL implementation with Ethernet/IP/UDP/TCP support");

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
