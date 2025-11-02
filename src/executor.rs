// src/executor.rs - Загрузчик и исполнитель .pim файлов
use crate::linker::{PimExecutable, PimHeader};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use x86_64::VirtAddr;

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

        // В реальной реализации здесь была бы загрузка в память процесса
        // Пока что просто симулируем загрузку

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
        let _process = self
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(ExecutorError::InvalidEntryPoint)?;

        // В упрощённой версии просто симулируем выполнение
        crate::println!("Process {} executed successfully (simulated)", pid);

        Ok(())
    }

    fn allocate_process_memory(&self, _size: usize) -> Result<VirtAddr, ExecutorError> {
        // Упрощённое выделение памяти
        let base_addr = 0x400000u64; // Стандартный адрес загрузки пользовательских программ
        Ok(VirtAddr::new(base_addr))
    }

    pub fn terminate_process(&mut self, pid: u32) -> Result<(), ExecutorError> {
        self.processes.retain(|p| p.pid != pid);
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

fn sys_read(_fd: i32, _buffer: u64, _count: u64) -> u64 {
    // Упрощённая реализация чтения
    0
}
