use crate::vga_buffer::Color;
use crate::{print, println, serial_println};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;

const BACKSPACE: u8 = 8;

lazy_static! {
    static ref COMMAND_BUFFER: Mutex<Option<String>> = Mutex::new(None);
    static ref CURRENT_PATH: Mutex<String> = Mutex::new("/".to_string());
}

pub fn shell_loop() -> ! {
    {
        let mut buffer = COMMAND_BUFFER.lock();
        *buffer = Some(String::new());
    }

    print_prompt();

    loop {
        x86_64::instructions::hlt();
    }
}

pub fn handle_key(character: char) {
    let mut buffer_guard = COMMAND_BUFFER.lock();
    if let Some(ref mut buffer) = *buffer_guard {
        if character == '\n' {
            println!();
            let cmd = buffer.trim().to_string();
            buffer.clear();
            drop(buffer_guard);
            process_command(&cmd);
            print_prompt();
        } else if character as u8 == BACKSPACE {
            if !buffer.is_empty() {
                buffer.pop();
                crate::vga_buffer::delete_byte();
            }
        } else if character.is_ascii() && !character.is_control() {
            buffer.push(character);
            print!("{}", character);
        }
    }
}

fn print_prompt() {
    crate::vga_buffer::write_colored_text("> ", Color::Yellow);
}

fn process_command(cmd: &str) {
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    if parts.is_empty() {
        return;
    }

    serial_println!("Command executed: {}", cmd);

    match parts[0] {
        "help" | "?" => {
            println!();
            crate::vga_buffer::write_colored_text("Available commands:", Color::White);
            println!();

            crate::vga_buffer::write_colored_text("System Commands:", Color::Cyan);
            println!("  help, ?              - Show this help message");
            println!("  clear, cls           - Clear the screen");
            println!("  echo <text>          - Print text to screen");
            println!("  version, ver         - Show OS version");
            println!("  meminfo              - Display memory information");
            println!("  reboot               - Reboot the system");
            println!();

            crate::vga_buffer::write_colored_text("File System Commands:", Color::Green);
            println!("  ls [path]            - List directory contents");
            println!("  mkdir <path>         - Create a directory");
            println!("  touch <path>         - Create an empty file");
            println!("  write <path> <text>  - Write text to file");
            println!("  cat <path>           - Display file contents");
            println!("  rm <path>            - Delete a file");
            println!("  rmdir <path>         - Remove directory");
            println!("  tree                 - Display directory tree");
            println!("  diskinfo             - Show disk usage");
            println!("  pwd                  - Print working directory");
            println!("  stat <path>          - Show file information");
            println!();

            crate::vga_buffer::write_colored_text("Network Commands:", Color::Magenta);
            println!("  ping <ip>            - Ping a remote host");
            println!("  netinfo              - Display network information");
            println!("  setip <ip>           - Set IP address");
        }
        "ping" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: ping <ip>", Color::LightRed);
                println!();
                return;
            }

            let ip_str = parts[1];
            match crate::network::Ipv4Address::from_str(ip_str) {
                Ok(ip) => {
                    crate::vga_buffer::write_colored_text("Pinging ", Color::Cyan);
                    crate::vga_buffer::write_colored_text(ip_str, Color::Yellow);
                    println!("...");
                    println!();

                    match crate::network::ping(ip) {
                        Ok(_) => {
                            crate::vga_buffer::write_colored_text("✓ Ping completed", Color::Green);
                            println!();
                        }
                        Err(e) => {
                            crate::vga_buffer::write_colored_text("✗ Ping failed: ", Color::Red);
                            println!("{}", e);
                        }
                    }
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "netinfo" => {
            crate::vga_buffer::write_colored_text("Network Information:", Color::White);
            println!();

            let info = crate::network::get_detailed_network_info();

            print!("  Status:      ");
            if info.is_initialized {
                crate::vga_buffer::write_colored_text("Online", Color::Green);
            } else {
                crate::vga_buffer::write_colored_text("Offline", Color::Red);
            }
            println!();

            print!("  IP Address:  ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{}", info.ip_address),
                Color::Cyan,
            );
            println!();

            print!("  MAC Address: ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{}", info.mac_address),
                Color::Yellow,
            );
            println!();

            print!("  Gateway:     ");
            crate::vga_buffer::write_colored_text(&alloc::format!("{}", info.gateway), Color::Cyan);
            println!();

            print!("  Netmask:     ");
            crate::vga_buffer::write_colored_text(&alloc::format!("{}", info.netmask), Color::Cyan);
            println!();

            println!();
            crate::vga_buffer::write_colored_text("Network Statistics:", Color::White);
            println!();
            println!("  Packets sent: {}", info.stats.packets_sent);
            println!("  Packets received: {}", info.stats.packets_received);
            println!("  Ping requests: {}", info.stats.ping_requests);
            println!("  Ping replies: {}", info.stats.ping_replies);
        }
        "setip" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: setip <ip>", Color::LightRed);
                println!();
                return;
            }

            match crate::network::set_ip_address(parts[1]) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓ IP address set to ", Color::Green);
                    crate::vga_buffer::write_colored_text(parts[1], Color::Cyan);
                    println!();
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "clear" | "cls" => {
            crate::vga_buffer::clear_screen();
        }
        "echo" => {
            if parts.len() > 1 {
                crate::vga_buffer::write_colored_text(&parts[1..].join(" "), Color::Magenta);
                println!();
            }
        }
        "version" | "ver" => {
            crate::vga_buffer::write_colored_text("PatapimOS version 0.3.0", Color::White);
            println!();
            crate::vga_buffer::write_colored_text("Built with Rust (bare-metal)", Color::Cyan);
            println!();
            crate::vga_buffer::write_colored_text(
                "Features: Serial Port, File System, Network Stack",
                Color::Green,
            );
            println!();
        }
        "meminfo" => {
            crate::vga_buffer::write_colored_text("Memory Information:", Color::White);
            println!();
            print!("  Heap start: ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{:#x}", crate::allocator::HEAP_START),
                Color::Yellow,
            );
            println!();
            print!("  Heap size:  ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{} KiB", crate::allocator::HEAP_SIZE / 1024),
                Color::Yellow,
            );
            println!();
        }
        "pwd" => {
            let current_path = CURRENT_PATH.lock();
            print!("Current directory: ");
            crate::vga_buffer::write_colored_text(&*current_path, Color::Green);
            println!();
        }
        "mkdir" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: mkdir <path>", Color::LightRed);
                println!();
                return;
            }
            let path = parts[1];
            let mut disk = crate::fs::RAMDISK.lock();
            match disk.mkdir(path) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓", Color::Green);
                    print!(" Directory '");
                    crate::vga_buffer::write_colored_text(path, Color::Green);
                    println!("' created");
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "touch" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: touch <path>", Color::LightRed);
                println!();
                return;
            }
            let path = parts[1];
            let mut disk = crate::fs::RAMDISK.lock();
            match disk.create_file(path, Vec::new()) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓", Color::Green);
                    print!(" File '");
                    crate::vga_buffer::write_colored_text(path, Color::Green);
                    println!("' created");
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "write" => {
            if parts.len() < 3 {
                crate::vga_buffer::write_colored_text(
                    "Usage: write <path> <content>",
                    Color::LightRed,
                );
                println!();
                return;
            }
            let path = parts[1];
            let content = parts[2..].join(" ");
            let mut disk = crate::fs::RAMDISK.lock();

            match disk.write_file(path, content.as_bytes().to_vec()) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓", Color::Green);
                    print!(" Content written to '");
                    crate::vga_buffer::write_colored_text(path, Color::Green);
                    println!("'");
                }
                Err(e) => {
                    if e == "File not found" {
                        match disk.create_file(path, content.as_bytes().to_vec()) {
                            Ok(_) => {
                                crate::vga_buffer::write_colored_text("✓", Color::Green);
                                print!(" File '");
                                crate::vga_buffer::write_colored_text(path, Color::Green);
                                println!("' created and written");
                            }
                            Err(e) => {
                                crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                                println!("{}", e);
                            }
                        }
                    } else {
                        crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                        println!("{}", e);
                    }
                }
            }
        }
        "cat" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: cat <path>", Color::LightRed);
                println!();
                return;
            }
            let path = parts[1];
            let disk = crate::fs::RAMDISK.lock();
            match disk.read_file(path) {
                Ok(content) => match String::from_utf8(content) {
                    Ok(text) => {
                        crate::vga_buffer::write_colored_text(
                            &alloc::format!("=== {} ===", path),
                            Color::Cyan,
                        );
                        println!();
                        crate::vga_buffer::write_colored_text(&text, Color::White);
                        println!();
                        crate::vga_buffer::write_colored_text("===================", Color::Cyan);
                        println!();
                    }
                    Err(_) => {
                        crate::vga_buffer::write_colored_text(
                            "✗ Error: File contains non-UTF8 data",
                            Color::Red,
                        );
                        println!();
                    }
                },
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "ls" => {
            let path = if parts.len() > 1 { parts[1] } else { "/" };
            let disk = crate::fs::RAMDISK.lock();
            match disk.list_directory(path) {
                Ok(entries) => {
                    crate::vga_buffer::write_colored_text(
                        &alloc::format!("Directory: {}", path),
                        Color::Cyan,
                    );
                    println!();
                    if entries.is_empty() {
                        println!("  (empty)");
                    } else {
                        for (name, file_type, size) in entries {
                            print!("  ");
                            if file_type == crate::fs::FileType::Directory {
                                crate::vga_buffer::write_colored_text("[DIR] ", Color::Blue);
                            } else {
                                crate::vga_buffer::write_colored_text("[FILE] ", Color::Green);
                            }
                            crate::vga_buffer::write_colored_text(&name, Color::Yellow);
                            crate::vga_buffer::write_colored_text(
                                &alloc::format!(" ({}B)", size),
                                Color::DarkGray,
                            );
                            println!();
                        }
                    }
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "tree" => {
            let disk = crate::fs::RAMDISK.lock();
            let tree = disk.get_tree();
            if tree.is_empty() {
                crate::vga_buffer::write_colored_text("File system is empty", Color::Yellow);
                println!();
            } else {
                crate::vga_buffer::write_colored_text("Directory tree:", Color::Cyan);
                println!();
                crate::vga_buffer::write_colored_text(&tree, Color::White);
            }
        }
        "rm" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: rm <path>", Color::LightRed);
                println!();
                return;
            }
            let path = parts[1];
            let mut disk = crate::fs::RAMDISK.lock();
            match disk.delete_file(path) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓", Color::Green);
                    print!(" File '");
                    crate::vga_buffer::write_colored_text(path, Color::Green);
                    println!("' deleted");
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "rmdir" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: rmdir <path>", Color::LightRed);
                println!();
                return;
            }
            let path = parts[1];
            let mut disk = crate::fs::RAMDISK.lock();
            match disk.delete_directory(path) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓", Color::Green);
                    print!(" Directory '");
                    crate::vga_buffer::write_colored_text(path, Color::Green);
                    println!("' deleted");
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "stat" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: stat <path>", Color::LightRed);
                println!();
                return;
            }
            let path = parts[1];
            let disk = crate::fs::RAMDISK.lock();
            match disk.get_file_size(path) {
                Ok(size) => {
                    print!("File '");
                    crate::vga_buffer::write_colored_text(path, Color::Green);
                    print!("' - Size: ");
                    crate::vga_buffer::write_colored_text(
                        &alloc::format!("{} bytes", size),
                        Color::Yellow,
                    );
                    println!();
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }
        "diskinfo" => {
            let disk = crate::fs::RAMDISK.lock();
            crate::vga_buffer::write_colored_text("RAM Disk Information:", Color::White);
            println!();
            println!("  Total size:  512 KB");
            print!("  Used:        ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{} bytes", disk.get_total_size()),
                Color::Yellow,
            );
            println!();
            print!("  Free:        ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{} bytes", disk.get_free_space()),
                Color::Green,
            );
            println!();
            print!("  Files:       ");
            crate::vga_buffer::write_colored_text(
                &alloc::format!("{}", disk.get_file_count()),
                Color::Cyan,
            );
            println!();
        }
        // Добавить к существующим командам:
        "cleardns" => match crate::network::clear_dns_cache() {
            Ok(_) => {
                crate::vga_buffer::write_colored_text("✓ DNS cache cleared", Color::Green);
                println!();
            }
            Err(e) => {
                crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                println!("{}", e);
            }
        },
        "dnscache" => {
            crate::vga_buffer::write_colored_text("DNS Cache Entries:", Color::White);
            println!();

            let entries = crate::network::get_dns_cache_entries();
            if entries.is_empty() {
                println!("  No entries in cache");
            } else {
                for (domain, ip, expire_time) in entries {
                    print!("  ");
                    crate::vga_buffer::write_colored_text(&domain, Color::Cyan);
                    print!(" -> ");
                    crate::vga_buffer::write_colored_text(&alloc::format!("{}", ip), Color::Yellow);
                    println!(" (expires: {})", expire_time);
                }
            }
        }
        "reboot" => {
            crate::vga_buffer::write_colored_text("Rebooting...", Color::LightRed);
            println!();
            serial_println!("System reboot requested");
            unsafe {
                use x86_64::instructions::port::Port;
                let mut port = Port::<u8>::new(0x64);
                port.write(0xFE);
            }
        }
        "" => {}
        _ => {
            crate::vga_buffer::write_colored_text("✗ Unknown command: ", Color::Red);
            print!("'");
            crate::vga_buffer::write_colored_text(parts[0], Color::LightRed);
            println!("'. Type 'help' for available commands.");
        }
    }
}
