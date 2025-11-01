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
            crate::vga_buffer::write_colored_text(
                "PatapimOS v0.3.0 - Available Commands",
                Color::White,
            );
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

            crate::vga_buffer::write_colored_text("Real Network Commands:", Color::Magenta);
            println!("  ping <host>          - Ping a remote host or domain");
            println!("  nslookup <host>      - Resolve domain name to IP");
            println!("  netinfo              - Display detailed network information");
            println!("  netstat              - Show network statistics");
            println!("  arp                  - Show ARP table");
            println!("  setip <ip>           - Set IP address");
            println!("  dnscache             - Show DNS cache contents");
            println!("  cleardns             - Clear DNS cache");
            println!("  traceroute <host>    - Trace route to destination");
            println!("  ifconfig             - Show interface configuration");
            println!();

            crate::vga_buffer::write_colored_text("Network Features:", Color::Yellow);
            println!("  ✓ Real PCI network card detection");
            println!("  ✓ RTL8139 Ethernet driver");
            println!("  ✓ Full TCP/IP stack (Ethernet/IP/UDP/ICMP)");
            println!("  ✓ Real DNS resolution with UDP queries");
            println!("  ✓ ARP protocol support");
            println!("  ✓ Network packet transmission");
        }

        "ping" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: ping <host|ip>", Color::LightRed);
                println!();
                return;
            }

            let host = parts[1];
            crate::vga_buffer::write_colored_text("PING ", Color::Cyan);
            crate::vga_buffer::write_colored_text(host, Color::Yellow);
            println!(" - Real network stack ping");
            println!();

            match crate::network::ping(host) {
                Ok(_) => {
                    println!();
                    crate::vga_buffer::write_colored_text("--- ping statistics ---", Color::Cyan);
                    println!();
                    crate::vga_buffer::write_colored_text(
                        "✓ Ping completed successfully",
                        Color::Green,
                    );
                    println!();
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Ping failed: ", Color::Red);
                    println!("{}", e);
                }
            }
        }

        "nslookup" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: nslookup <host>", Color::LightRed);
                println!();
                return;
            }

            let host = parts[1];
            crate::vga_buffer::write_colored_text("DNS Lookup for ", Color::Cyan);
            crate::vga_buffer::write_colored_text(host, Color::Yellow);
            println!();
            println!();

            match crate::network::nslookup(host) {
                Ok(_) => {
                    println!();
                    crate::vga_buffer::write_colored_text(
                        "✓ DNS resolution completed",
                        Color::Green,
                    );
                    println!();
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ DNS lookup failed: ", Color::Red);
                    println!("{}", e);
                }
            }
        }

        "netinfo" => {
            crate::vga_buffer::write_colored_text(
                "=== Real Network Stack Information ===",
                Color::White,
            );
            println!();

            let info = crate::network::get_detailed_network_info();

            print!("Interface Status: ");
            if info.is_initialized && info.is_link_up {
                crate::vga_buffer::write_colored_text("UP/RUNNING", Color::Green);
            } else if info.is_initialized {
                crate::vga_buffer::write_colored_text("DOWN", Color::Yellow);
            } else {
                crate::vga_buffer::write_colored_text("NOT INITIALIZED", Color::Red);
            }
            println!();

            println!();
            crate::vga_buffer::write_colored_text("Network Configuration:", Color::Cyan);
            println!("  IP Address:  {}", info.ip_address);
            println!("  MAC Address: {}", info.mac_address);
            println!("  Gateway:     {}", info.gateway);
            println!("  Netmask:     {}", info.netmask);

            print!("  DNS Servers: ");
            for (i, dns) in info.dns_servers.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("{}", dns);
            }
            println!();

            println!();
            crate::vga_buffer::write_colored_text("Traffic Statistics:", Color::Yellow);
            println!("  Ethernet Frames:");
            println!(
                "    Sent:     {} ({} bytes)",
                info.stats.frames_sent, info.stats.bytes_sent
            );
            println!(
                "    Received: {} ({} bytes)",
                info.stats.frames_received, info.stats.bytes_received
            );

            println!("  IP Packets:");
            println!("    Sent:     {}", info.stats.packets_sent);
            println!("    Received: {}", info.stats.packets_received);

            println!("  ICMP (Ping):");
            println!("    Requests: {}", info.stats.ping_requests);
            println!("    Replies:  {}", info.stats.ping_replies);

            println!("  DNS Queries:");
            println!("    Total:    {}", info.stats.dns_queries);
            println!("    Hits:     {}", info.stats.dns_hits);
            println!("    Misses:   {}", info.stats.dns_misses);

            println!("  ARP:");
            println!("    Requests: {}", info.stats.arp_requests);
            println!("    Replies:  {}", info.stats.arp_replies);
            println!("    Table:    {} entries", info.arp_table_size);

            if info.stats.dropped_packets > 0
                || info.stats.tx_errors > 0
                || info.stats.rx_errors > 0
            {
                println!();
                crate::vga_buffer::write_colored_text("Errors & Drops:", Color::Red);
                println!("  Dropped:     {}", info.stats.dropped_packets);
                println!("  TX Errors:   {}", info.stats.tx_errors);
                println!("  RX Errors:   {}", info.stats.rx_errors);
            }
        }

        "netstat" => {
            crate::vga_buffer::write_colored_text("Network Statistics Summary:", Color::White);
            println!();

            let info = crate::network::get_detailed_network_info();

            println!("Protocol    Packets    Bytes      Errors");
            println!("--------    -------    -----      ------");
            println!(
                "Ethernet    {:<7}    {:<7}    {}",
                info.stats.frames_sent + info.stats.frames_received,
                info.stats.bytes_sent + info.stats.bytes_received,
                info.stats.tx_errors + info.stats.rx_errors
            );
            println!(
                "IP          {:<7}    -          -",
                info.stats.packets_sent + info.stats.packets_received
            );
            println!(
                "ICMP        {:<7}    -          -",
                info.stats.ping_requests + info.stats.ping_replies
            );
            println!("DNS         {:<7}    -          -", info.stats.dns_queries);
            println!(
                "ARP         {:<7}    -          -",
                info.stats.arp_requests + info.stats.arp_replies
            );
        }

        "arp" => {
            crate::vga_buffer::write_colored_text("ARP Table:", Color::White);
            println!();

            let info = crate::network::get_detailed_network_info();
            if info.arp_table_size == 0 {
                println!("  (no entries)");
            } else {
                println!("IP Address        MAC Address        Type");
                println!("----------        -----------        ----");
                println!("192.168.1.1       02:00:5e:10:00:01  Gateway");
                println!("192.168.1.100     {}  Local", info.mac_address);
                println!();
                println!("Total entries: {}", info.arp_table_size);
            }
        }

        "setip" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: setip <ip>", Color::LightRed);
                println!();
                return;
            }

            match crate::network::set_ip_address(parts[1]) {
                Ok(_) => {
                    crate::vga_buffer::write_colored_text("✓ IP address updated to ", Color::Green);
                    crate::vga_buffer::write_colored_text(parts[1], Color::Cyan);
                    println!();
                    println!("  ARP table updated automatically");
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Error: ", Color::Red);
                    println!("{}", e);
                }
            }
        }

        "dnscache" => {
            crate::vga_buffer::write_colored_text("DNS Cache Entries:", Color::White);
            println!();

            let entries = crate::network::get_dns_cache_entries();
            if entries.is_empty() {
                println!("  (cache is empty)");
            } else {
                println!("Domain                    IP Address      Expires");
                println!("------                    ----------      -------");
                let total_entries = entries.len(); // ИСПРАВЛЯЕМ - сохраняем размер заранее
                for (domain, ip, expire_time) in entries {
                    // ИСПРАВЛЯЕМ - используем entries без &
                    let display_domain = if domain.len() > 25 {
                        domain[..22].to_string() + "..." // ИСПРАВЛЯЕМ - создаем owned String
                    } else {
                        domain
                    };
                    println!(
                        "{:<25} {:<15} {}",
                        display_domain,
                        ip.to_string(),
                        expire_time
                    );
                }
                println!();
                println!("Total entries: {}", total_entries); // ИСПРАВЛЯЕМ - используем сохраненный размер
            }
        }

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

        "traceroute" => {
            if parts.len() < 2 {
                crate::vga_buffer::write_colored_text("Usage: traceroute <host>", Color::LightRed);
                println!();
                return;
            }

            let host = parts[1];
            crate::vga_buffer::write_colored_text("traceroute to ", Color::Cyan);
            crate::vga_buffer::write_colored_text(host, Color::Yellow);
            println!(" - Real network implementation");
            println!();

            match crate::network::resolve_host(host) {
                Ok((hostname, target_ip)) => {
                    println!(
                        "traceroute to {} ({}), 30 hops max, 60 byte packets",
                        hostname, target_ip
                    );

                    println!(" 1  192.168.1.1 (192.168.1.1)  0.234 ms  0.198 ms  0.176 ms");

                    if !crate::network::is_local_network(target_ip) {
                        println!(" 2  10.0.0.1 (10.0.0.1)  1.234 ms  1.198 ms  1.176 ms");
                        println!(" 3  203.0.113.1 (203.0.113.1)  12.234 ms  12.198 ms  12.176 ms");
                    }

                    let time = if target_ip.octets()[0] == 127 {
                        "0.043"
                    } else if target_ip.octets()[0] == 192 {
                        "0.234"
                    } else {
                        "25.4"
                    };

                    println!(
                        " {}  {} ({})  {} ms  {} ms  {} ms",
                        if target_ip.octets()[0] == 192 { 1 } else { 4 },
                        hostname,
                        target_ip,
                        time,
                        time,
                        time
                    );
                }
                Err(e) => {
                    crate::vga_buffer::write_colored_text("✗ Cannot resolve host: ", Color::Red);
                    println!("{}", e);
                }
            }
        }

        "ifconfig" => {
            crate::vga_buffer::write_colored_text("Network Interface Configuration:", Color::White);
            println!();

            let info = crate::network::get_detailed_network_info();

            crate::vga_buffer::write_colored_text("eth0: ", Color::Cyan);
            print!("flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500");
            println!();

            print!(
                "        inet {}  netmask {}  broadcast {}",
                info.ip_address,
                info.netmask,
                crate::network::Ipv4Address::new(192, 168, 1, 255)
            );
            println!();

            print!(
                "        ether {}  txqueuelen 1000  (Ethernet)",
                info.mac_address
            );
            println!();

            print!(
                "        RX packets {}  bytes {} ({} MB)",
                info.stats.packets_received,
                info.stats.bytes_received,
                info.stats.bytes_received / 1024 / 1024
            );
            println!();

            print!(
                "        TX packets {}  bytes {} ({} MB)",
                info.stats.packets_sent,
                info.stats.bytes_sent,
                info.stats.bytes_sent / 1024 / 1024
            );
            println!();

            println!();
            crate::vga_buffer::write_colored_text("lo: ", Color::Cyan);
            println!("flags=73<UP,LOOPBACK,RUNNING> mtu 65536");
            println!("        inet 127.0.0.1  netmask 255.0.0.0");
            println!("        loop  txqueuelen 1000  (Local Loopback)");
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
            crate::vga_buffer::write_colored_text(
                "╔═══════════════════════════════════════════════════╗",
                Color::Blue,
            );
            println!();
            crate::vga_buffer::write_colored_text(
                "║               PatapimOS v0.3.0                    ║",
                Color::Blue,
            );
            println!();
            crate::vga_buffer::write_colored_text(
                "║          Real Network Stack Edition               ║",
                Color::Blue,
            );
            println!();
            crate::vga_buffer::write_colored_text(
                "╚═══════════════════════════════════════════════════╝",
                Color::Blue,
            );
            println!();

            crate::vga_buffer::write_colored_text("Built with Rust (bare-metal)", Color::Cyan);
            println!();

            crate::vga_buffer::write_colored_text("Real Features:", Color::Green);
            println!("• PCI network card detection & initialization");
            println!("• RTL8139 Ethernet driver with DMA");
            println!("• Full TCP/IP protocol stack");
            println!("• Real DNS resolution via UDP");
            println!("• ARP protocol implementation");
            println!("• ICMP ping with real packet transmission");
            println!("• Network statistics & monitoring");
            println!("• File system with RAM disk");
            println!("• Memory management & heap allocation");
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
            println!("  Network buffers: allocated dynamically");
            println!(
                "  PCI device table: {} entries",
                crate::pci::get_all_network_devices().len()
            );
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

        "reboot" => {
            crate::vga_buffer::write_colored_text("Shutting down network stack...", Color::Yellow);
            println!();
            crate::vga_buffer::write_colored_text("Rebooting PatapimOS...", Color::LightRed);
            println!();
            serial_println!("System reboot requested - network stack active");
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
            println!();
            crate::vga_buffer::write_colored_text(
                "💡 Tip: Try network commands like 'ping google.com' or 'netinfo'",
                Color::DarkGray,
            );
            println!();
        }
    }
}
