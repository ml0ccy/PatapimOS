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
    RTL8139,    // Realtek RTL8139
    RTL8169,    // Realtek RTL8169
    E1000,      // Intel E1000
    E1000E,     // Intel E1000E
    VirtIO,     // VirtIO Network
    PCNet,      // AMD PCNet
    Intel82540, // Intel 82540
    Intel82545, // Intel 82545
    Intel82574, // Intel 82574
    Broadcom,   // Broadcom NetXtreme
    Generic,    // Generic Ethernet adapter
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
    pub bar0: u32,
    pub bar1: u32,
    pub irq: u8,
    pub card_type: NetworkCardType,
}

impl PciDevice {
    pub fn get_io_base(&self) -> Option<u16> {
        if self.bar0 & 1 != 0 {
            Some((self.bar0 & !3) as u16)
        } else {
            None
        }
    }

    pub fn get_memory_base(&self) -> Option<u32> {
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
    crate::serial_println!("PCI: Starting comprehensive bus enumeration");
    scan_pci_bus();

    let devices = PCI_DEVICES.lock();
    crate::serial_println!("PCI: Found {} total devices", devices.len());

    let network_devices: Vec<&PciDevice> = devices
        .iter()
        .filter(|dev| dev.class_code == PCI_CLASS_NETWORK && dev.subclass == PCI_SUBCLASS_ETHERNET)
        .collect();

    crate::serial_println!("PCI: Found {} network adapters", network_devices.len());

    for (i, device) in network_devices.iter().enumerate() {
        crate::serial_println!(
            "PCI: Network adapter {} - Vendor: 0x{:04X}, Device: 0x{:04X}, Type: {:?}",
            i + 1,
            device.vendor_id,
            device.device_id,
            device.card_type
        );

        if let Some(io_base) = device.get_io_base() {
            crate::serial_println!("     I/O Base: 0x{:04X}", io_base);
        }
        if let Some(mem_base) = device.get_memory_base() {
            crate::serial_println!("     Memory Base: 0x{:08X}", mem_base);
        }
        crate::serial_println!("     IRQ: {}", device.irq);
    }

    if network_devices.is_empty() {
        crate::serial_println!("PCI: WARNING - No network adapters found");
        crate::serial_println!("PCI: Creating virtual network adapter for testing");

        // Создаем виртуальный сетевой адаптер для тестирования
        let virtual_device = PciDevice {
            bus: 0,
            slot: 0,
            function: 0,
            vendor_id: 0x10EC,
            device_id: 0x8139,
            class_code: PCI_CLASS_NETWORK,
            subclass: PCI_SUBCLASS_ETHERNET,
            bar0: 0xC001, // I/O space at 0xC000
            bar1: 0,
            irq: 11,
            card_type: NetworkCardType::RTL8139,
        };

        drop(devices);
        let mut devices_mut = PCI_DEVICES.lock();
        devices_mut.push(virtual_device);

        crate::serial_println!("PCI: Virtual RTL8139 adapter created");
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
        return;
    }

    check_pci_function(bus, slot, 0);

    let header_type = pci_config_read_u8(bus, slot, 0, 0x0E);
    if header_type & 0x80 != 0 {
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

        crate::serial_println!(
            "PCI: Found real network device at {:02X}:{:02X}.{} - {:04X}:{:04X}",
            bus,
            slot,
            function,
            vendor_id,
            device_id
        );
    }
}

/// Определение типа сетевой карты по vendor/device ID
fn identify_network_card(vendor_id: u16, device_id: u16) -> NetworkCardType {
    match (vendor_id, device_id) {
        // Realtek
        (0x10EC, 0x8139) => NetworkCardType::RTL8139,
        (0x10EC, 0x8169) | (0x10EC, 0x8168) | (0x10EC, 0x8167) => NetworkCardType::RTL8169,

        // Intel E1000 семейство
        (0x8086, 0x100E) => NetworkCardType::E1000,
        (0x8086, 0x1004) | (0x8086, 0x100F) | (0x8086, 0x1010) | (0x8086, 0x1012) => {
            NetworkCardType::E1000
        }
        (0x8086, 0x10B9) | (0x8086, 0x10BA) | (0x8086, 0x10BB) => NetworkCardType::E1000E,
        (0x8086, 0x1015) | (0x8086, 0x1016) | (0x8086, 0x1017) => NetworkCardType::Intel82540,
        (0x8086, 0x1018) | (0x8086, 0x1019) | (0x8086, 0x101A) => NetworkCardType::Intel82545,
        (0x8086, 0x10D3) | (0x8086, 0x10D4) | (0x8086, 0x10D5) => NetworkCardType::Intel82574,

        // VirtIO Network (QEMU/KVM)
        (0x1AF4, 0x1000) | (0x1AF4, 0x1041) => NetworkCardType::VirtIO,

        // AMD PCNet
        (0x1022, 0x2000) | (0x1022, 0x2001) => NetworkCardType::PCNet,

        // Broadcom
        (0x14E4, _) => NetworkCardType::Broadcom,

        // Любой другой сетевой адаптер - поддерживаем как Generic
        _ => NetworkCardType::Generic,
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
    let new_command = command | 0x04 | 0x02 | 0x01; // Bus Master + Memory Space + I/O Space

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
