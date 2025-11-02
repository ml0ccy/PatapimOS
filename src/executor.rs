// src/executor.rs - Загрузчик и исполнитель .pim файлов
use crate::linker::{PimExecutable, PimHeader};
use crate::memory;
use alloc::string::String;
use alloc::vec::Vec;
use x86_64::{
    structures::paging::{Page, PageTableFlags, Size4KiB},
    VirtAddr,
};

#[derive(Debug)]
pub enum ExecutorError {
    InvalidFormat,
    MemoryAllocationFailed,
    UnsupportedVersion,
    InvalidEntryPoint,
}

pub struct ProcessContext {
    pub pid: u32,
    pub memory_base: VirtAddr,
    pub code_size: usize,
    pub data_size: usize,
    pub entry_point: VirtAddr,
    pub registers: ProcessRegisters,
}

#[derive(Debug, Default)]
pub struct ProcessRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub struct Executor {
    next_pid: u32,
    processes: Vec<ProcessContext>,
}

impl Executor {
    pub fn new() -> Self {
        Self {
            next_pid: 1,
            processes: Vec::new(),
        }
    }

    pub fn load_pim(&mut self, pim_data: &[u8]) -> Result<u32, ExecutorError> {
        // Парсим заголовок
        if pim_data.len() < 32 {
            return Err(ExecutorError::InvalidFormat);
        }

        let header = PimHeader::from_bytes(pim_data).map_err(|_| ExecutorError::InvalidFormat)?;

        if header.version != 1 {
            return Err(ExecutorError::UnsupportedVersion);
        }

        // Выделяем память для процесса
        let total_size = header.code_size + header.data_size;
        let memory_base = self.allocate_process_memory(total_size as usize)?;

        // Загружаем код
        let code_start = 32; // После заголовка
        let code_end = code_start + header.code_size as usize;

        if pim_data.len() < code_end {
            return Err(ExecutorError::InvalidFormat);
        }

        unsafe {
            let code_ptr = memory_base.as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(
                pim_data[code_start..code_end].as_ptr(),
                code_ptr,
                header.code_size as usize,
            );
        }

        // Загружаем данные
        if header.data_size > 0 {
            let data_start = code_end;
            let data_end = data_start + header.data_size as usize;

            if pim_data.len() < data_end {
                return Err(ExecutorError::InvalidFormat);
            }

            unsafe {
                let data_ptr = memory_base
                    .as_mut_ptr::<u8>()
                    .add(header.code_size as usize);
                core::ptr::copy_nonoverlapping(
                    pim_data[data_start..data_end].as_ptr(),
                    data_ptr,
                    header.data_size as usize,
                );
            }
        }

        // Создаём контекст процесса
        let pid = self.next_pid;
        self.next_pid += 1;

        let mut context = ProcessContext {
            pid,
            memory_base,
            code_size: header.code_size as usize,
            data_size: header.data_size as usize,
            entry_point: VirtAddr::new(header.entry_point),
            registers: ProcessRegisters::default(),
        };

        // Настраиваем стек
        context.registers.rsp = (memory_base.as_u64() + total_size as u64 + 0x1000) & !0xF;
        context.registers.rbp = context.registers.rsp;
        context.registers.rip = header.entry_point;

        self.processes.push(context);
        Ok(pid)
    }

    pub fn execute(&mut self, pid: u32) -> Result<(), ExecutorError> {
        let process = self
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(ExecutorError::InvalidEntryPoint)?;

        // Переключаемся в пользовательский режим и выполняем код
        // Это упрощённая версия - в реальной ОС здесь был бы переход в Ring 3
        self.execute_user_code(process)?;

        Ok(())
    }

    fn execute_user_code(&self, process: &ProcessContext) -> Result<(), ExecutorError> {
        // Устанавливаем регистры процессора
        unsafe {
            asm!(
                "mov rax, {}",
                "mov rbx, {}",
                "mov rcx, {}",
                "mov rdx, {}",
                "mov rsi, {}",
                "mov rdi, {}",
                "mov rsp, {}",
                "mov rbp, {}",
                "jmp {}",
                in(reg) process.registers.rax,
                in(reg) process.registers.rbx,
                in(reg) process.registers.rcx,
                in(reg) process.registers.rdx,
                in(reg) process.registers.rsi,
                in(reg) process.registers.rdi,
                in(reg) process.registers.rsp,
                in(reg) process.registers.rbp,
                in(reg) process.entry_point.as_u64(),
                options(noreturn)
            );
        }
    }

    fn allocate_process_memory(&self, size: usize) -> Result<VirtAddr, ExecutorError> {
        // Упрощённое выделение памяти
        // В реальной реализации нужно использовать memory allocator
        let pages_needed = (size + 0xFFF) / 0x1000;
        let base_addr = 0x400000u64; // Стандартный адрес загрузки пользовательских программ

        // Здесь должна быть интеграция с системой управления памятью PatapimOS
        Ok(VirtAddr::new(base_addr))
    }

    pub fn terminate_process(&mut self, pid: u32) -> Result<(), ExecutorError> {
        self.processes.retain(|p| p.pid != pid);
        // Освобождаем память процесса
        Ok(())
    }

    pub fn get_process_info(&self, pid: u32) -> Option<&ProcessContext> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    pub fn list_processes(&self) -> Vec<u32> {
        self.processes.iter().map(|p| p.pid).collect()
    }
}

// Системные вызовы для .pim программ
pub fn handle_syscall(syscall_num: u64, args: &[u64]) -> u64 {
    match syscall_num {
        1 => sys_exit(args[0] as i32),
        2 => sys_write(args[0] as i32, args[1], args[2]),
        3 => sys_read(args[0] as i32, args[1], args[2]),
        _ => u64::MAX, // Неизвестный системный вызов
    }
}

fn sys_exit(exit_code: i32) -> u64 {
    // Завершение процесса
    crate::println!("Process exited with code: {}", exit_code);
    0
}

fn sys_write(fd: i32, buffer: u64, count: u64) -> u64 {
    if fd == 1 {
        // stdout
        unsafe {
            let slice = core::slice::from_raw_parts(buffer as *const u8, count as usize);
            if let Ok(s) = core::str::from_utf8(slice) {
                crate::print!("{}", s);
                return count;
            }
        }
    }
    u64::MAX
}

fn sys_read(fd: i32, buffer: u64, count: u64) -> u64 {
    // Упрощённая реализация чтения
    // В реальной версии здесь была бы работа с файловой системой
    0
}
