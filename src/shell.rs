use crate::vga_buffer::Color;
use crate::{print, println, serial_println};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const BACKSPACE: u8 = 8;

pub static mut COMMAND_BUFFER: Option<String> = None;
pub static mut CURRENT_PATH: &'static str = "/";

pub fn shell_loop() -> ! {
    unsafe {
        COMMAND_BUFFER = Some(String::new());
    }

    print_prompt();

    loop {
        x86_64::instructions::hlt();
    }
}

pub fn handle_key(character: char) {
    unsafe {
        if let Some(ref mut buffer) = COMMAND_BUFFER {
            if character == '\n' {
                println!();
                process_command(buffer.trim());
                buffer.clear();
                print_prompt();
            } else if character as u8 == BACKSPACE {
                if !buffer.is_empty() {
                    buffer.pop();
                    crate::vga_buffer::delete_byte();
                    // Перерисовываем оставшийся текст с правильными цветами
                    if !buffer.is_empty() {
                        redraw_command_line(buffer);
                    }
                }
            } else if character.is_ascii() && !character.is_control() {
                buffer.push(character);
                print_char_colored(buffer);
            }
        }
    }
}

fn print_prompt() {
    crate::vga_buffer::write_colored_text("> ", Color::Yellow);
}

fn get_command_parts(buffer: &str) -> Vec<&str> {
    buffer.split_whitespace().collect()
}

fn get_color_for_part(command: &str, part_index: usize) -> Color {
    match command {
        "echo" => {
            if part_index == 0 {
                Color::Cyan // команда
            } else {
                Color::Magenta // текст
            }
        }
        "write" => {
            if part_index == 0 {
                Color::Cyan // команда
            } else if part_index == 1 {
                Color::Green // путь
            } else {
                Color::Magenta // содержимое
            }
        }
        "mkdir" | "touch" | "cat" | "rm" | "rmdir" | "stat" | "ls" => {
            if part_index == 0 {
                Color::Cyan // команда
            } else {
                Color::Green // путь
            }
        }
        "help" | "?" | "clear" | "cls" | "version" | "ver" | "meminfo" | "pwd" | "tree"
        | "diskinfo" | "reboot" => {
            Color::Cyan // только команда
        }
        _ => {
            if part_index == 0 {
                Color::LightRed // неизвестная команда
            } else {
                Color::White // аргументы
            }
        }
    }
}

fn redraw_command_line(buffer: &str) {
    let parts = get_command_parts(buffer);

    if parts.is_empty() {
        return;
    }

    // Удаляем текущую строку (удаляем каждый символ команды)
    for _ in 0..buffer.len() {
        crate::vga_buffer::delete_byte();
    }

    // Перерисовываем всю команду с цветами
    print_colored_command(buffer);
}

fn print_char_colored(buffer: &str) {
    let parts = get_command_parts(buffer);

    if parts.is_empty() {
        return;
    }

    let command = parts[0];
    let current_word_index = parts.len() - 1;

    let last_char = buffer.chars().last().unwrap_or(' ');

    let color = get_color_for_part(command, current_word_index);

    let mut char_string = String::new();
    char_string.push(last_char);
    crate::vga_buffer::write_colored_text(&char_string, color);
}

fn print_colored_command(buffer: &str) {
    let parts = get_command_parts(buffer);

    if parts.is_empty() {
        return;
    }

    let command = parts[0];

    // Выводим первую часть (команда)
    crate::vga_buffer::write_colored_text(command, Color::Cyan);

    // Выводим остальные части с соответствующими цветами
    for (idx, part) in parts.iter().enumerate().skip(1) {
        print!(" ");
        let color = get_color_for_part(command, idx);
        crate::vga_buffer::write_colored_text(part, color);
    }

    // Если в буфере есть пробел в конце, добавляем его
    if let Some(last_char) = buffer.chars().last() {
        if last_char == ' ' {
            print!(" ");
        }
    }
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
                "Features: Serial Port, Hierarchical File System",
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
        "pwd" => unsafe {
            print!("Current directory: ");
            crate::vga_buffer::write_colored_text(CURRENT_PATH, Color::Green);
            println!();
        },
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
