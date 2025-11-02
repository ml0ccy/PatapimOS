// src/linker.rs - Линкер PatapimOS
use crate::pasm::{ObjectFile, Relocation, RelocationType, Symbol};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct PimExecutable {
    pub header: PimHeader,
    pub code: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PimHeader {
    pub magic: [u8; 4],   // "PIM\0"
    pub version: u32,     // Версия формата
    pub entry_point: u64, // Точка входа
    pub code_size: u32,   // Размер секции кода
    pub data_size: u32,   // Размер секции данных
    pub flags: u32,       // Флаги исполняемого файла
}

impl PimHeader {
    pub fn new() -> Self {
        Self {
            magic: [b'P', b'I', b'M', 0],
            version: 1,
            entry_point: 0,
            code_size: 0,
            data_size: 0,
            flags: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.entry_point.to_le_bytes());
        bytes.extend_from_slice(&self.code_size.to_le_bytes());
        bytes.extend_from_slice(&self.data_size.to_le_bytes());
        bytes.extend_from_slice(&self.flags.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 32 {
            return Err("Header too small".to_string());
        }

        let mut header = Self::new();
        header.magic.copy_from_slice(&bytes[0..4]);
        header.version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        header.entry_point = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        header.code_size = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        header.data_size = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        header.flags = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);

        if &header.magic != b"PIM\0" {
            return Err("Invalid PIM magic".to_string());
        }

        Ok(header)
    }
}

pub struct Linker {
    objects: Vec<ObjectFile>,
    symbol_table: BTreeMap<String, u64>,
    code: Vec<u8>,
    data: Vec<u8>,
    base_address: u64,
}

impl Linker {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            symbol_table: BTreeMap::new(),
            code: Vec::new(),
            data: Vec::new(),
            base_address: 0x1000, // Базовый адрес загрузки
        }
    }

    pub fn add_object(&mut self, object: ObjectFile) {
        self.objects.push(object);
    }

    pub fn link(&mut self) -> Result<PimExecutable, String> {
        // Этап 1: Собираем все символы
        self.collect_symbols()?;

        // Этап 2: Объединяем секции
        self.merge_sections();

        // Этап 3: Разрешаем релокации
        self.resolve_relocations()?;

        // Этап 4: Создаём исполняемый файл
        let mut header = PimHeader::new();
        header.code_size = self.code.len() as u32;
        header.data_size = self.data.len() as u32;

        // Ищем точку входа
        if let Some(&entry) = self.symbol_table.get("_start") {
            header.entry_point = entry;
        } else if let Some(&entry) = self.symbol_table.get("main") {
            header.entry_point = entry;
        } else {
            header.entry_point = self.base_address; // По умолчанию начало кода
        }

        Ok(PimExecutable {
            header,
            code: self.code.clone(),
            data: self.data.clone(),
        })
    }

    fn collect_symbols(&mut self) -> Result<(), String> {
        let mut code_offset = 0u64;
        let mut data_offset = 0u64;

        for object in &self.objects {
            // Добавляем символы из кода
            for symbol in &object.symbols {
                let address = match symbol.symbol_type {
                    crate::pasm::SymbolType::Function | crate::pasm::SymbolType::Label => {
                        self.base_address + code_offset + symbol.address
                    }
                    crate::pasm::SymbolType::Variable => {
                        self.base_address + 0x10000 + data_offset + symbol.address
                    }
                };

                if self.symbol_table.contains_key(&symbol.name) {
                    return Err(format!("Duplicate symbol: {}", symbol.name));
                }

                self.symbol_table.insert(symbol.name.clone(), address);
            }

            code_offset += object.instructions.len() as u64;
            data_offset += object.data.len() as u64;
        }

        Ok(())
    }

    fn merge_sections(&mut self) {
        self.code.clear();
        self.data.clear();

        // Объединяем код
        for object in &self.objects {
            self.code.extend_from_slice(&object.instructions);
        }

        // Объединяем данные
        for object in &self.objects {
            self.data.extend_from_slice(&object.data);
        }
    }

    fn resolve_relocations(&mut self) -> Result<(), String> {
        let mut code_offset = 0usize;

        for object in &self.objects {
            for relocation in &object.relocations {
                let symbol_addr = self
                    .symbol_table
                    .get(&relocation.symbol)
                    .ok_or_else(|| format!("Undefined symbol: {}", relocation.symbol))?;

                let patch_offset = code_offset + relocation.offset as usize;

                match relocation.reloc_type {
                    RelocationType::Absolute => {
                        // Абсолютный адрес
                        let bytes = symbol_addr.to_le_bytes();
                        for (i, &byte) in bytes.iter().enumerate() {
                            if patch_offset + i < self.code.len() {
                                self.code[patch_offset + i] = byte;
                            }
                        }
                    }
                    RelocationType::Relative => {
                        // Относительный адрес
                        let current_addr = self.base_address + patch_offset as u64;
                        let offset = (*symbol_addr as i64) - (current_addr as i64);

                        if offset >= i32::MIN as i64 && offset <= i32::MAX as i64 {
                            let bytes = (offset as i32).to_le_bytes();
                            for (i, &byte) in bytes.iter().enumerate() {
                                if patch_offset + i < self.code.len() {
                                    self.code[patch_offset + i] = byte;
                                }
                            }
                        } else {
                            return Err("Relocation offset too large".to_string());
                        }
                    }
                }
            }

            code_offset += object.instructions.len();
        }

        Ok(())
    }

    pub fn save_executable(&self, executable: &PimExecutable) -> Vec<u8> {
        let mut output = Vec::new();

        // Добавляем заголовок
        output.extend_from_slice(&executable.header.to_bytes());

        // Добавляем код
        output.extend_from_slice(&executable.code);

        // Добавляем данные
        output.extend_from_slice(&executable.data);

        output
    }
}
