//! PCI (Peripheral Component Interconnect) подсистема для поиска и инициализации сетевых карт
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::port::{Port, PortWriteOnly};

/// PCI Configuration Space регистры
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI класс и подкласс для сетевых адаптеров
const PCI_CLASS_NETWORK: u8 = 0x02;
const PCI_SUBCLASS_ETHERNET: u8 = 0x00;

/// Известные сетевые устройства
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkCardType {
    RTL8139, // Realtek RTL8139
    E1000,   // Intel E1000
    VirtIO,  // VirtIO Network
    PCNet,   // AMD PCNet
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub bar0: u32, // Base Address Register 0
    pub bar1: u32, // Base Address Register 1
    pub irq: u8,   // IRQ линия
    pub card_type: NetworkCardType,
}

impl PciDevice {
    pub fn get_io_base(&self) -> Option<u16> {
        // BAR0 для I/O портов (бит 0 = 1 означает I/O space)
        if self.bar0 & 1 != 0 {
            Some((self.bar0 & !3) as u16)
        } else {
            None
        }
    }

    pub fn get_memory_base(&self) -> Option<u32> {
        // BAR0 для Memory Mapped I/O (бит 0 = 0 означает Memory space)
        if self.bar0 & 1 == 0 {
            Some(self.bar0 & !0xF)
        } else {
            None
        }
    }
}

lazy_static! {
    static ref PCI_DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());
    static ref CONFIG_ADDRESS_PORT: Mutex<PortWriteOnly<u32>> =
        Mutex::new(PortWriteOnly::new(PCI_CONFIG_ADDRESS));
    static ref CONFIG_DATA_PORT: Mutex<Port<u32>> = Mutex::new(Port::new(PCI_CONFIG_DATA));
}

/// Инициализация PCI подсистемы
pub fn init_pci() -> Result<(), &'static str> {
    crate::serial_println!("PCI: Starting bus enumeration");
    scan_pci_bus();

    let devices = PCI_DEVICES.lock();
    crate::serial_println!("PCI: Found {} total devices", devices.len());

    let network_devices: Vec<&PciDevice> = devices
        .iter()
        .filter(|dev| dev.class_code == PCI_CLASS_NETWORK && dev.subclass == PCI_SUBCLASS_ETHERNET)
        .collect();

    if network_devices.is_empty() {
        crate::serial_println!("PCI: No network adapters found");
        return Err("No network adapters found");
    }

    for device in &network_devices {
        crate::serial_println!(
            "PCI: Found network adapter - Vendor: 0x{:04X}, Device: 0x{:04X}, Type: {:?}",
            device.vendor_id,
            device.device_id,
            device.card_type
        );

        if let Some(io_base) = device.get_io_base() {
            crate::serial_println!("     I/O Base: 0x{:04X}, IRQ: {}", io_base, device.irq);
        }
        if let Some(mem_base) = device.get_memory_base() {
            crate::serial_println!("     Memory Base: 0x{:08X}", mem_base);
        }
    }

    Ok(())
}

/// Сканирование PCI шины
fn scan_pci_bus() {
    for bus in 0..=255 {
        scan_pci_slots(bus as u8);
    }
}

fn scan_pci_slots(bus: u8) {
    for slot in 0..32 {
        scan_pci_functions(bus, slot);
    }
}

fn scan_pci_functions(bus: u8, slot: u8) {
    let vendor_id = pci_config_read_u16(bus, slot, 0, 0);
    if vendor_id == 0xFFFF {
        return; // Устройство отсутствует
    }

    // Проверяем функцию 0
    check_pci_function(bus, slot, 0);

    // Проверяем, является ли устройство многофункциональным
    let header_type = pci_config_read_u8(bus, slot, 0, 0x0E);
    if header_type & 0x80 != 0 {
        // Многофункциональное устройство - проверяем остальные функции
        for function in 1..8 {
            let func_vendor_id = pci_config_read_u16(bus, slot, function, 0);
            if func_vendor_id != 0xFFFF {
                check_pci_function(bus, slot, function);
            }
        }
    }
}

fn check_pci_function(bus: u8, slot: u8, function: u8) {
    let vendor_id = pci_config_read_u16(bus, slot, function, 0);
    let device_id = pci_config_read_u16(bus, slot, function, 2);
    let class_code = pci_config_read_u8(bus, slot, function, 0x0B);
    let subclass = pci_config_read_u8(bus, slot, function, 0x0A);

    // Проверяем только сетевые устройства
    if class_code == PCI_CLASS_NETWORK && subclass == PCI_SUBCLASS_ETHERNET {
        let bar0 = pci_config_read_u32(bus, slot, function, 0x10);
        let bar1 = pci_config_read_u32(bus, slot, function, 0x14);
        let irq = pci_config_read_u8(bus, slot, function, 0x3C);

        let card_type = identify_network_card(vendor_id, device_id);

        let device = PciDevice {
            bus,
            slot,
            function,
            vendor_id,
            device_id,
            class_code,
            subclass,
            bar0,
            bar1,
            irq,
            card_type,
        };

        let mut devices = PCI_DEVICES.lock();
        devices.push(device);
    }
}

/// Определение типа сетевой карты по vendor/device ID
fn identify_network_card(vendor_id: u16, device_id: u16) -> NetworkCardType {
    match (vendor_id, device_id) {
        // Realtek RTL8139
        (0x10EC, 0x8139) => NetworkCardType::RTL8139,

        // Intel E1000 семейство
        (0x8086, 0x100E)
        | (0x8086, 0x1004)
        | (0x8086, 0x100F)
        | (0x8086, 0x1010)
        | (0x8086, 0x1012) => NetworkCardType::E1000,

        // VirtIO Network (QEMU/KVM)
        (0x1AF4, 0x1000) => NetworkCardType::VirtIO,

        // AMD PCNet
        (0x1022, 0x2000) => NetworkCardType::PCNet,

        _ => NetworkCardType::Unknown,
    }
}

/// Чтение из PCI конфигурационного пространства
fn pci_config_read_u32(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32);

    unsafe {
        let mut addr_port = CONFIG_ADDRESS_PORT.lock();
        let mut data_port = CONFIG_DATA_PORT.lock();

        addr_port.write(address);
        data_port.read()
    }
}

fn pci_config_read_u16(bus: u8, slot: u8, function: u8, offset: u8) -> u16 {
    let data = pci_config_read_u32(bus, slot, function, offset);
    let shift = (offset & 2) * 8;
    (data >> shift) as u16
}

fn pci_config_read_u8(bus: u8, slot: u8, function: u8, offset: u8) -> u8 {
    let data = pci_config_read_u32(bus, slot, function, offset);
    let shift = (offset & 3) * 8;
    (data >> shift) as u8
}

/// Запись в PCI конфигурационное пространство
#[allow(dead_code)]
fn pci_config_write_u32(bus: u8, slot: u8, function: u8, offset: u8, value: u32) {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32);

    unsafe {
        let mut addr_port = CONFIG_ADDRESS_PORT.lock();
        let mut data_port = CONFIG_DATA_PORT.lock();

        addr_port.write(address);
        data_port.write(value);
    }
}

/// Получить первую найденную сетевую карту
pub fn get_primary_network_device() -> Option<PciDevice> {
    let devices = PCI_DEVICES.lock();
    devices
        .iter()
        .find(|dev| dev.class_code == PCI_CLASS_NETWORK && dev.subclass == PCI_SUBCLASS_ETHERNET)
        .cloned()
}

/// Получить все сетевые устройства
pub fn get_all_network_devices() -> Vec<PciDevice> {
    let devices = PCI_DEVICES.lock();
    devices
        .iter()
        .filter(|dev| dev.class_code == PCI_CLASS_NETWORK && dev.subclass == PCI_SUBCLASS_ETHERNET)
        .cloned()
        .collect()
}

/// Включение Bus Mastering для устройства (необходимо для DMA)
pub fn enable_bus_mastering(device: &PciDevice) {
    let command_reg_offset = 0x04;
    let command = pci_config_read_u16(device.bus, device.slot, device.function, command_reg_offset);
    let new_command = command | 0x04; // Устанавливаем бит Bus Master Enable

    let address = 0x80000000u32
        | ((device.bus as u32) << 16)
        | ((device.slot as u32) << 11)
        | ((device.function as u32) << 8)
        | ((command_reg_offset & 0xFC) as u32);

    unsafe {
        let mut addr_port = CONFIG_ADDRESS_PORT.lock();
        let mut data_port = CONFIG_DATA_PORT.lock();

        addr_port.write(address);
        let current_data = data_port.read();
        let new_data = (current_data & 0xFFFF0000) | (new_command as u32);

        addr_port.write(address);
        data_port.write(new_data);
    }

    crate::serial_println!(
        "PCI: Bus mastering enabled for device {:02X}:{:02X}.{}",
        device.bus,
        device.slot,
        device.function
    );
}
