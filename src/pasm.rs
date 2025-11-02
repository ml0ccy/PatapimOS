// src/pasm.rs - Ассемблер PatapimOS
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub enum Instruction {
    Mov(Operand, Operand),
    Add(Operand, Operand),
    Sub(Operand, Operand),
    Mul(Operand),
    Div(Operand),
    Cmp(Operand, Operand),
    Je(String),
    Jne(String),
    Jmp(String),
    Call(String),
    Ret,
    Push(Operand),
    Pop(Operand),
    Int(u8),
    Hlt,
    Nop,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Register(Register),
    Immediate(i32),
    Memory(i32),
    Label(String),
}

#[derive(Debug, Clone)]
pub enum Register {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rsp,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub symbol_type: SymbolType,
}

#[derive(Debug, Clone)]
pub enum SymbolType {
    Function,
    Variable,
    Label,
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u64,
    pub symbol: String,
    pub reloc_type: RelocationType,
}

#[derive(Debug, Clone)]
pub enum RelocationType {
    Absolute,
    Relative,
}

pub struct ObjectFile {
    pub instructions: Vec<u8>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub data: Vec<u8>,
}

pub struct Assembler {
    labels: BTreeMap<String, u64>,
    symbols: Vec<Symbol>,
    relocations: Vec<Relocation>,
    code: Vec<u8>,
    data: Vec<u8>,
    current_address: u64,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            labels: BTreeMap::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            code: Vec::new(),
            data: Vec::new(),
            current_address: 0,
        }
    }

    pub fn assemble(&mut self, source: &str) -> Result<ObjectFile, String> {
        // Первый проход - собираем метки
        self.first_pass(source)?;

        // Второй проход - генерируем код
        self.second_pass(source)?;

        Ok(ObjectFile {
            instructions: self.code.clone(),
            symbols: self.symbols.clone(),
            relocations: self.relocations.clone(),
            data: self.data.clone(),
        })
    }

    fn first_pass(&mut self, source: &str) -> Result<(), String> {
        let mut address = 0u64;

        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            if line.ends_with(':') {
                // Это метка
                let label = line[..line.len() - 1].to_string();
                self.labels.insert(label.clone(), address);
                self.symbols.push(Symbol {
                    name: label,
                    address,
                    symbol_type: SymbolType::Label,
                });
            } else {
                // Это инструкция, увеличиваем адрес
                address += self.estimate_instruction_size(line)?;
            }
        }

        Ok(())
    }

    fn second_pass(&mut self, source: &str) -> Result<(), String> {
        self.current_address = 0;

        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.ends_with(':') {
                continue;
            }

            let instruction = self.parse_instruction(line)?;
            self.encode_instruction(instruction)?;
        }

        Ok(())
    }

    fn parse_instruction(&self, line: &str) -> Result<Instruction, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Empty instruction".to_string());
        }

        let opcode = parts[0].to_lowercase();

        match opcode.as_str() {
            "mov" => {
                if parts.len() != 3 {
                    return Err("MOV requires 2 operands".to_string());
                }
                let dest = self.parse_operand(parts[1].trim_end_matches(','))?;
                let src = self.parse_operand(parts[2])?;
                Ok(Instruction::Mov(dest, src))
            }
            "add" => {
                if parts.len() != 3 {
                    return Err("ADD requires 2 operands".to_string());
                }
                let dest = self.parse_operand(parts[1].trim_end_matches(','))?;
                let src = self.parse_operand(parts[2])?;
                Ok(Instruction::Add(dest, src))
            }
            "sub" => {
                if parts.len() != 3 {
                    return Err("SUB requires 2 operands".to_string());
                }
                let dest = self.parse_operand(parts[1].trim_end_matches(','))?;
                let src = self.parse_operand(parts[2])?;
                Ok(Instruction::Sub(dest, src))
            }
            "cmp" => {
                if parts.len() != 3 {
                    return Err("CMP requires 2 operands".to_string());
                }
                let op1 = self.parse_operand(parts[1].trim_end_matches(','))?;
                let op2 = self.parse_operand(parts[2])?;
                Ok(Instruction::Cmp(op1, op2))
            }
            "je" => {
                if parts.len() != 2 {
                    return Err("JE requires 1 operand".to_string());
                }
                Ok(Instruction::Je(parts[1].to_string()))
            }
            "jne" => {
                if parts.len() != 2 {
                    return Err("JNE requires 1 operand".to_string());
                }
                Ok(Instruction::Jne(parts[1].to_string()))
            }
            "jmp" => {
                if parts.len() != 2 {
                    return Err("JMP requires 1 operand".to_string());
                }
                Ok(Instruction::Jmp(parts[1].to_string()))
            }
            "call" => {
                if parts.len() != 2 {
                    return Err("CALL requires 1 operand".to_string());
                }
                Ok(Instruction::Call(parts[1].to_string()))
            }
            "ret" => Ok(Instruction::Ret),
            "push" => {
                if parts.len() != 2 {
                    return Err("PUSH requires 1 operand".to_string());
                }
                let op = self.parse_operand(parts[1])?;
                Ok(Instruction::Push(op))
            }
            "pop" => {
                if parts.len() != 2 {
                    return Err("POP requires 1 operand".to_string());
                }
                let op = self.parse_operand(parts[1])?;
                Ok(Instruction::Pop(op))
            }
            "int" => {
                if parts.len() != 2 {
                    return Err("INT requires 1 operand".to_string());
                }
                let interrupt = parts[1]
                    .parse::<u8>()
                    .map_err(|_| "Invalid interrupt number")?;
                Ok(Instruction::Int(interrupt))
            }
            "hlt" => Ok(Instruction::Hlt),
            "nop" => Ok(Instruction::Nop),
            _ => Err(format!("Unknown instruction: {}", opcode)),
        }
    }

    fn parse_operand(&self, operand: &str) -> Result<Operand, String> {
        if operand.starts_with('%') {
            // Регистр
            let reg_name = &operand[1..];
            let register = match reg_name.to_lowercase().as_str() {
                "rax" => Register::Rax,
                "rbx" => Register::Rbx,
                "rcx" => Register::Rcx,
                "rdx" => Register::Rdx,
                "rsi" => Register::Rsi,
                "rdi" => Register::Rdi,
                "rsp" => Register::Rsp,
                "rbp" => Register::Rbp,
                "r8" => Register::R8,
                "r9" => Register::R9,
                "r10" => Register::R10,
                "r11" => Register::R11,
                "r12" => Register::R12,
                "r13" => Register::R13,
                "r14" => Register::R14,
                "r15" => Register::R15,
                _ => return Err(format!("Unknown register: {}", reg_name)),
            };
            Ok(Operand::Register(register))
        } else if operand.starts_with('$') {
            // Непосредственное значение
            let value = operand[1..]
                .parse::<i32>()
                .map_err(|_| "Invalid immediate value")?;
            Ok(Operand::Immediate(value))
        } else if operand.parse::<i32>().is_ok() {
            // Адрес памяти
            let addr = operand.parse::<i32>().unwrap();
            Ok(Operand::Memory(addr))
        } else {
            // Метка
            Ok(Operand::Label(operand.to_string()))
        }
    }

    fn encode_instruction(&mut self, instruction: Instruction) -> Result<(), String> {
        match instruction {
            Instruction::Mov(dest, src) => {
                self.emit_byte(0x48); // REX prefix
                self.emit_byte(0x89); // MOV opcode
                self.encode_operands(&dest, &src)?;
            }
            Instruction::Add(dest, src) => {
                self.emit_byte(0x48); // REX prefix
                self.emit_byte(0x01); // ADD opcode
                self.encode_operands(&dest, &src)?;
            }
            Instruction::Sub(dest, src) => {
                self.emit_byte(0x48); // REX prefix
                self.emit_byte(0x29); // SUB opcode
                self.encode_operands(&dest, &src)?;
            }
            Instruction::Cmp(op1, op2) => {
                self.emit_byte(0x48); // REX prefix
                self.emit_byte(0x39); // CMP opcode
                self.encode_operands(&op1, &op2)?;
            }
            Instruction::Je(label) => {
                self.emit_byte(0x74); // JE opcode
                self.encode_jump(&label)?;
            }
            Instruction::Jne(label) => {
                self.emit_byte(0x75); // JNE opcode
                self.encode_jump(&label)?;
            }
            Instruction::Jmp(label) => {
                self.emit_byte(0xEB); // JMP short opcode
                self.encode_jump(&label)?;
            }
            Instruction::Call(label) => {
                self.emit_byte(0xE8); // CALL opcode
                self.encode_call(&label)?;
            }
            Instruction::Ret => {
                self.emit_byte(0xC3); // RET opcode
            }
            Instruction::Push(op) => match op {
                Operand::Register(reg) => {
                    self.emit_byte(0x50 + self.register_code(&reg));
                }
                _ => return Err("PUSH only supports registers".to_string()),
            },
            Instruction::Pop(op) => match op {
                Operand::Register(reg) => {
                    self.emit_byte(0x58 + self.register_code(&reg));
                }
                _ => return Err("POP only supports registers".to_string()),
            },
            Instruction::Int(interrupt) => {
                self.emit_byte(0xCD); // INT opcode
                self.emit_byte(interrupt);
            }
            Instruction::Hlt => {
                self.emit_byte(0xF4); // HLT opcode
            }
            Instruction::Nop => {
                self.emit_byte(0x90); // NOP opcode
            }
            _ => return Err("Instruction not implemented".to_string()),
        }

        Ok(())
    }

    fn encode_operands(&mut self, dest: &Operand, src: &Operand) -> Result<(), String> {
        // Упрощённая кодировка - только регистры
        match (dest, src) {
            (Operand::Register(dest_reg), Operand::Register(src_reg)) => {
                let modrm =
                    0xC0 | (self.register_code(src_reg) << 3) | self.register_code(dest_reg);
                self.emit_byte(modrm);
            }
            (Operand::Register(dest_reg), Operand::Immediate(value)) => {
                let modrm = 0xC0 | self.register_code(dest_reg);
                self.emit_byte(modrm);
                self.emit_dword(*value as u32);
            }
            _ => return Err("Operand combination not supported".to_string()),
        }
        Ok(())
    }

    fn encode_jump(&mut self, label: &str) -> Result<(), String> {
        if let Some(&target_addr) = self.labels.get(label) {
            let offset = (target_addr as i32) - (self.current_address as i32) - 2;
            if offset >= -128 && offset <= 127 {
                self.emit_byte(offset as u8);
            } else {
                return Err("Jump offset too large".to_string());
            }
        } else {
            // Добавляем релокацию
            self.relocations.push(Relocation {
                offset: self.current_address,
                symbol: label.to_string(),
                reloc_type: RelocationType::Relative,
            });
            self.emit_byte(0x00); // Placeholder
        }
        Ok(())
    }

    fn encode_call(&mut self, label: &str) -> Result<(), String> {
        if let Some(&target_addr) = self.labels.get(label) {
            let offset = (target_addr as i32) - (self.current_address as i32) - 5;
            self.emit_dword(offset as u32);
        } else {
            // Добавляем релокацию
            self.relocations.push(Relocation {
                offset: self.current_address,
                symbol: label.to_string(),
                reloc_type: RelocationType::Relative,
            });
            self.emit_dword(0x00000000); // Placeholder
        }
        Ok(())
    }

    fn register_code(&self, register: &Register) -> u8 {
        match register {
            Register::Rax => 0,
            Register::Rcx => 1,
            Register::Rdx => 2,
            Register::Rbx => 3,
            Register::Rsp => 4,
            Register::Rbp => 5,
            Register::Rsi => 6,
            Register::Rdi => 7,
            Register::R8 => 8,
            Register::R9 => 9,
            Register::R10 => 10,
            Register::R11 => 11,
            Register::R12 => 12,
            Register::R13 => 13,
            Register::R14 => 14,
            Register::R15 => 15,
        }
    }

    fn emit_byte(&mut self, byte: u8) {
        self.code.push(byte);
        self.current_address += 1;
    }

    fn emit_dword(&mut self, dword: u32) {
        self.code.extend_from_slice(&dword.to_le_bytes());
        self.current_address += 4;
    }

    fn estimate_instruction_size(&self, line: &str) -> Result<u64, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(0);
        }

        match parts[0].to_lowercase().as_str() {
            "mov" | "add" | "sub" | "cmp" => Ok(3), // REX + opcode + ModR/M
            "je" | "jne" => Ok(2),                  // opcode + offset
            "jmp" => Ok(2),                         // short jump
            "call" => Ok(5),                        // opcode + 4-byte offset
            "ret" | "hlt" | "nop" => Ok(1),
            "push" | "pop" => Ok(1),
            "int" => Ok(2),
            _ => Err(format!("Unknown instruction: {}", parts[0])),
        }
    }
}
