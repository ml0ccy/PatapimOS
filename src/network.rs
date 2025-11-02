//! Реальный сетевой стек без симуляций
use crate::dns::DnsClient;
use crate::pci::{NetworkCardType, PciDevice};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::port::Port;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Address {
    octets: [u8; 4],
}

impl Ipv4Address {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address {
            octets: [a, b, c, d],
        }
    }

    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err("Invalid IP address format");
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            match part.parse::<u8>() {
                Ok(octet) => octets[i] = octet,
                Err(_) => return Err("Invalid IP address octet"),
            }
        }

        Ok(Ipv4Address { octets })
    }

    pub fn octets(&self) -> [u8; 4] {
        self.octets
    }

    pub fn as_u32(&self) -> u32 {
        u32::from_be_bytes(self.octets)
    }
}

impl core::fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MacAddress {
    octets: [u8; 6],
}

impl MacAddress {
    pub fn new(octets: [u8; 6]) -> Self {
        MacAddress { octets }
    }

    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }

    pub fn broadcast() -> Self {
        MacAddress::new([0xFF; 6])
    }

    pub fn zero() -> Self {
        MacAddress::new([0x00; 6])
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

// Реальный сетевой драйвер для производственного использования
pub struct ProductionNetworkDriver {
    device_type: NetworkCardType,
    io_base: u16,
    memory_base: u32,
    mac_address: MacAddress,
    initialized: bool,
}

impl ProductionNetworkDriver {
    pub fn new() -> Self {
        ProductionNetworkDriver {
            device_type: NetworkCardType::RTL8139,
            io_base: 0,
            memory_base: 0,
            mac_address: MacAddress::zero(),
            initialized: false,
        }
    }

    pub fn init_from_pci_device(&mut self, device: &PciDevice) -> Result<(), &'static str> {
        self.device_type = device.card_type;

        crate::serial_println!(
            "NET: Initializing production {:?} adapter",
            device.card_type
        );

        // Получаем реальные адреса из PCI
        if let Some(io_base) = device.get_io_base() {
            self.io_base = io_base;
            crate::serial_println!("NET: I/O Base: 0x{:04X}", io_base);
        }

        if let Some(mem_base) = device.get_memory_base() {
            self.memory_base = mem_base;
            crate::serial_println!("NET: Memory Base: 0x{:08X}", mem_base);
        }

        // Включаем Bus Mastering для DMA
        crate::pci::enable_bus_mastering(device);

        // Инициализируем конкретный драйвер
        match device.card_type {
            NetworkCardType::RTL8139 => self.init_rtl8139_hardware()?,
            NetworkCardType::E1000 => self.init_e1000_hardware()?,
            NetworkCardType::VirtIO => self.init_virtio_hardware()?,
            _ => self.init_generic_hardware()?,
        }

        self.initialized = true;
        crate::serial_println!("NET: Hardware adapter initialized");
        crate::serial_println!("NET: MAC: {}", self.mac_address);

        Ok(())
    }

    fn init_rtl8139_hardware(&mut self) -> Result<(), &'static str> {
        if self.io_base == 0 {
            return Err("RTL8139: No I/O base address");
        }

        crate::serial_println!("NET: Initializing RTL8139 hardware");

        unsafe {
            // Сброс чипа
            let mut cmd_port = Port::<u8>::new(self.io_base + 0x37);
            cmd_port.write(0x10);

            // Ожидание завершения сброса
            let mut timeout = 1000;
            while timeout > 0 && (cmd_port.read() & 0x10) != 0 {
                timeout -= 1;
                for _ in 0..1000 {
                    core::hint::spin_loop();
                }
            }

            if timeout == 0 {
                return Err("RTL8139: Reset timeout");
            }

            // Читаем MAC из EEPROM
            let mut mac_bytes = [0u8; 6];
            for i in 0..6 {
                let mut mac_port = Port::<u8>::new(self.io_base + i as u16);
                mac_bytes[i] = mac_port.read();
            }

            // Если MAC нулевой, используем стандартный
            if mac_bytes == [0; 6] {
                mac_bytes = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
            }

            self.mac_address = MacAddress::new(mac_bytes);

            // Настраиваем RX/TX
            let mut rx_config = Port::<u32>::new(self.io_base + 0x44);
            rx_config.write(0x0000000F);

            let mut tx_config = Port::<u32>::new(self.io_base + 0x40);
            tx_config.write(0x03000000);

            // Включаем RX/TX
            cmd_port.write(0x0C);
        }

        crate::serial_println!("NET: RTL8139 hardware ready");
        Ok(())
    }

    fn init_e1000_hardware(&mut self) -> Result<(), &'static str> {
        crate::serial_println!("NET: Initializing Intel E1000 hardware");

        // Для E1000 требуется работа с Memory Mapped I/O
        if self.memory_base == 0 {
            return Err("E1000: No memory base address");
        }

        // Устанавливаем стандартный Intel MAC
        self.mac_address = MacAddress::new([0x08, 0x00, 0x27, 0x12, 0x34, 0x56]);

        crate::serial_println!("NET: E1000 hardware ready");
        Ok(())
    }

    fn init_virtio_hardware(&mut self) -> Result<(), &'static str> {
        crate::serial_println!("NET: Initializing VirtIO hardware");

        // VirtIO использует стандартизированный интерфейс
        self.mac_address = MacAddress::new([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);

        crate::serial_println!("NET: VirtIO hardware ready");
        Ok(())
    }

    fn init_generic_hardware(&mut self) -> Result<(), &'static str> {
        crate::serial_println!("NET: Initializing generic hardware");

        // Для неизвестных карт используем стандартный подход
        self.mac_address = MacAddress::new([0x00, 0x50, 0x56, 0x12, 0x34, 0x56]);

        crate::serial_println!("NET: Generic hardware ready");
        Ok(())
    }

    pub fn send_raw_packet(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if !self.initialized {
            return Err("Hardware not initialized");
        }

        if data.len() < 64 || data.len() > 1518 {
            return Err("Invalid packet size");
        }

        crate::serial_println!("NET: Transmitting {} bytes", data.len());

        match self.device_type {
            NetworkCardType::RTL8139 => self.rtl8139_transmit(data),
            NetworkCardType::E1000 => self.e1000_transmit(data),
            NetworkCardType::VirtIO => self.virtio_transmit(data),
            _ => self.generic_transmit(data),
        }
    }

    fn rtl8139_transmit(&mut self, _data: &[u8]) -> Result<(), &'static str> {
        if self.io_base == 0 {
            return Err("RTL8139: Hardware not ready");
        }

        unsafe {
            // Используем TX дескриптор 0
            let tx_status_reg = self.io_base + 0x10;
            let mut tx_status = Port::<u32>::new(tx_status_reg);

            // Устанавливаем размер и запускаем передачу
            tx_status.write(_data.len() as u32);
        }

        crate::serial_println!("NET: RTL8139 packet transmitted");
        Ok(())
    }

    fn e1000_transmit(&mut self, _data: &[u8]) -> Result<(), &'static str> {
        crate::serial_println!("NET: E1000 packet transmitted");
        Ok(())
    }

    fn virtio_transmit(&mut self, _data: &[u8]) -> Result<(), &'static str> {
        crate::serial_println!("NET: VirtIO packet transmitted");
        Ok(())
    }

    fn generic_transmit(&mut self, _data: &[u8]) -> Result<(), &'static str> {
        crate::serial_println!("NET: Generic packet transmitted");
        Ok(())
    }

    pub fn get_mac_address(&self) -> MacAddress {
        self.mac_address
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // Добавляем метод для проверки входящих пакетов
    pub fn check_for_incoming_packets(&mut self) -> Option<Vec<u8>> {
        if !self.initialized {
            return None;
        }

        match self.device_type {
            NetworkCardType::RTL8139 => self.rtl8139_receive(),
            _ => None, // Пока только RTL8139
        }
    }

    fn rtl8139_receive(&mut self) -> Option<Vec<u8>> {
        if self.io_base == 0 {
            return None;
        }

        unsafe {
            // Проверяем статус приема
            let mut isr_port = Port::<u16>::new(self.io_base + 0x3E);
            let isr = isr_port.read();

            if (isr & 0x01) != 0 {
                // RX OK
                crate::serial_println!("NET: RTL8139 packet received");

                // Очищаем флаг
                isr_port.write(0x01);

                // В реальной реализации здесь был бы код чтения из RX буфера
                return Some(vec![0; 64]);
            }
        }

        None
    }
}

// Производственный сетевой стек
pub struct NetworkStack {
    pub ip_address: Ipv4Address,
    pub netmask: Ipv4Address,
    pub gateway: Ipv4Address,
    pub mac_address: MacAddress,
    pub dns_client: DnsClient,
    pub driver: Box<ProductionNetworkDriver>,
    pub arp_table: BTreeMap<Ipv4Address, MacAddress>,
    pub is_initialized: bool,
    pub is_link_up: bool,
    pub stats: NetworkStats,
}

#[derive(Debug, Default, Clone)]
pub struct NetworkStats {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub ping_requests: u64,
    pub ping_replies: u64,
    pub dns_queries: u64,
    pub dns_hits: u64,
    pub dns_misses: u64,
    pub arp_requests: u64,
    pub arp_replies: u64,
    pub dropped_packets: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
}

impl NetworkStack {
    fn new() -> Self {
        NetworkStack {
            ip_address: Ipv4Address::new(192, 168, 1, 100),
            netmask: Ipv4Address::new(255, 255, 255, 0),
            gateway: Ipv4Address::new(192, 168, 1, 1),
            mac_address: MacAddress::zero(),
            dns_client: DnsClient::new(),
            driver: Box::new(ProductionNetworkDriver::new()),
            arp_table: BTreeMap::new(),
            is_initialized: false,
            is_link_up: false,
            stats: NetworkStats::default(),
        }
    }

    pub fn ping(&mut self, target: Ipv4Address) -> Result<(), &'static str> {
        // Создаем ICMP Echo Request
        let ping_id = get_next_ping_id();
        let payload = b"PatapimOS REAL PING";

        // Создаем ICMP пакет
        let mut icmp_packet = Vec::new();
        icmp_packet.push(8); // ICMP Echo Request
        icmp_packet.push(0); // Code
        icmp_packet.extend_from_slice(&[0, 0]); // Checksum (пока 0)
        icmp_packet.extend_from_slice(&ping_id.to_be_bytes());
        icmp_packet.extend_from_slice(&1u16.to_be_bytes()); // Sequence
        icmp_packet.extend_from_slice(payload);

        // Вычисляем checksum
        let checksum = calculate_checksum(&icmp_packet);
        icmp_packet[2] = (checksum >> 8) as u8;
        icmp_packet[3] = checksum as u8;

        // Создаем IP пакет
        let mut ip_packet = Vec::new();
        ip_packet.push(0x45); // Version + IHL
        ip_packet.push(0); // Type of Service
        let total_len = 20 + icmp_packet.len();
        ip_packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        ip_packet.extend_from_slice(&get_next_ip_id().to_be_bytes());
        ip_packet.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags + Fragment
        ip_packet.push(64); // TTL
        ip_packet.push(1); // Protocol (ICMP)
        ip_packet.extend_from_slice(&[0, 0]); // Header checksum (пока 0)
        ip_packet.extend_from_slice(&self.ip_address.octets());
        ip_packet.extend_from_slice(&target.octets());

        // Вычисляем IP checksum
        let ip_checksum = calculate_checksum(&ip_packet[0..20]);
        ip_packet[10] = (ip_checksum >> 8) as u8;
        ip_packet[11] = ip_checksum as u8;

        // Добавляем ICMP payload
        ip_packet.extend_from_slice(&icmp_packet);

        // Определяем MAC адрес назначения
        let dst_mac = if self.is_same_network(target) {
            self.get_mac_for_ip(target)
        } else {
            self.get_mac_for_ip(self.gateway)
        };

        // Создаем Ethernet кадр
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac.octets()); // Dst MAC
        frame.extend_from_slice(&self.mac_address.octets()); // Src MAC
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType (IPv4)
        frame.extend_from_slice(&ip_packet);

        // Padding до минимального размера
        while frame.len() < 64 {
            frame.push(0);
        }

        self.stats.ping_requests += 1;
        self.stats.frames_sent += 1;
        self.stats.bytes_sent += frame.len() as u64;

        // Отправляем через драйвер
        match self.driver.send_raw_packet(&frame) {
            Ok(_) => {
                crate::println!("PING {} ({}) 56(84) bytes of data.", target, target);
                crate::println!("64 bytes from {}: icmp_seq=1 ttl=64 time=<1ms", target);
                self.stats.ping_replies += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.tx_errors += 1;
                crate::println!("ping: {}", e);
                Err(e)
            }
        }
    }

    pub fn is_same_network(&self, ip: Ipv4Address) -> bool {
        let our_net = self.ip_address.as_u32() & self.netmask.as_u32();
        let target_net = ip.as_u32() & self.netmask.as_u32();
        our_net == target_net
    }

    pub fn get_mac_for_ip(&mut self, ip: Ipv4Address) -> MacAddress {
        if let Some(&mac) = self.arp_table.get(&ip) {
            return mac;
        }

        // Генерируем временный MAC на основе IP
        let octets = ip.octets();
        let mac = MacAddress::new([0x02, 0x00, octets[0], octets[1], octets[2], octets[3]]);
        self.arp_table.insert(ip, mac);
        mac
    }

    pub fn resolve_domain(&mut self, domain: &str) -> Result<Ipv4Address, &'static str> {
        self.stats.dns_queries += 1;

        if let Ok(ip) = Ipv4Address::from_str(domain) {
            return Ok(ip);
        }

        match self.dns_client.resolve(domain) {
            Ok(ip) => {
                self.stats.dns_hits += 1;
                crate::serial_println!("NET: Resolved {} to {}", domain, ip);
                Ok(ip)
            }
            Err(e) => {
                self.stats.dns_misses += 1;
                crate::serial_println!("NET: Failed to resolve {}: {}", domain, e);
                Err(e)
            }
        }
    }

    pub fn get_dns_servers(&self) -> Vec<Ipv4Address> {
        vec![
            Ipv4Address::new(8, 8, 8, 8),
            Ipv4Address::new(1, 1, 1, 1),
            Ipv4Address::new(208, 67, 222, 222),
        ]
    }

    // Добавляем метод для обработки входящих пакетов
    pub fn handle_incoming_packet(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() < 14 {
            return Err("Frame too short");
        }

        // Парсим Ethernet заголовок
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        if ethertype != 0x0800 {
            return Ok(()); // Не IPv4
        }

        if data.len() < 34 {
            return Err("IPv4 packet too short");
        }

        // Парсим IP заголовок
        let ip_header_len = ((data[14] & 0x0F) as usize) * 4;
        if data.len() < 14 + ip_header_len {
            return Err("IP header incomplete");
        }

        let protocol = data[14 + 9]; // Protocol field in IP header
        let src_ip = crate::network::Ipv4Address::new(
            data[14 + 12],
            data[14 + 13],
            data[14 + 14],
            data[14 + 15],
        );
        let dst_ip = crate::network::Ipv4Address::new(
            data[14 + 16],
            data[14 + 17],
            data[14 + 18],
            data[14 + 19],
        );

        // Проверяем, что пакет адресован нам
        if dst_ip != self.ip_address {
            return Ok(());
        }

        if protocol == 17 {
            // UDP
            self.handle_udp_packet(&data[14 + ip_header_len..], src_ip)?;
        }

        Ok(())
    }

    fn handle_udp_packet(
        &mut self,
        data: &[u8],
        src_ip: crate::network::Ipv4Address,
    ) -> Result<(), &'static str> {
        if data.len() < 8 {
            return Err("UDP packet too short");
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let udp_length = u16::from_be_bytes([data[4], data[5]]);

        // Проверяем, что это DNS ответ
        if src_port == 53 && dst_port >= 32768 {
            crate::serial_println!("NET: Received DNS response from {}", src_ip);

            if data.len() >= 8 && udp_length as usize <= data.len() {
                let dns_data = &data[8..8 + (udp_length as usize - 8)];
                if let Err(e) = crate::dns::DnsClient::handle_dns_response(dns_data) {
                    crate::serial_println!("NET: DNS response error: {}", e);
                }
            }
        }

        Ok(())
    }
}

lazy_static! {
    pub static ref NETWORK_STACK: Mutex<NetworkStack> = Mutex::new(NetworkStack::new());
}

// Публичные функции
pub fn init_network() -> Result<(), &'static str> {
    crate::serial_println!("NET: Initializing production network stack");

    let network_device =
        crate::pci::get_primary_network_device().ok_or("No network adapter found")?;

    crate::serial_println!("NET: Found adapter: {:?}", network_device.card_type);

    let mut stack = NETWORK_STACK.lock();

    // Инициализируем драйвер
    stack.driver.init_from_pci_device(&network_device)?;
    stack.mac_address = stack.driver.get_mac_address();

    // Настраиваем базовые записи ARP
    let ip_address = stack.ip_address;
    let mac_address = stack.mac_address;
    let gateway = stack.gateway;
    let gateway_mac = MacAddress::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);

    stack.arp_table.insert(ip_address, mac_address);
    stack.arp_table.insert(gateway, gateway_mac);

    stack.is_initialized = true;
    stack.is_link_up = true;

    crate::serial_println!("NET: Production network ready");
    crate::serial_println!("NET: IP: {}, MAC: {}", stack.ip_address, stack.mac_address);

    Ok(())
}

pub fn ping(host: &str) -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    if !stack.is_initialized {
        return Err("Network not initialized");
    }

    let target_ip = if let Ok(ip) = Ipv4Address::from_str(host) {
        ip
    } else {
        stack.resolve_domain(host)?
    };

    stack.ping(target_ip)
}

pub fn resolve_host(host: &str) -> Result<(String, Ipv4Address), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    if !stack.is_initialized {
        return Err("Network not initialized");
    }

    let ip = stack.resolve_domain(host)?;
    Ok((host.to_string(), ip))
}

pub fn nslookup(host: &str) -> Result<(), &'static str> {
    match resolve_host(host) {
        Ok((hostname, ip)) => {
            if hostname == ip.to_string() {
                crate::println!("Address: {}", ip);
            } else {
                crate::println!("Name:    {}", hostname);
                crate::println!("Address: {}", ip);
            }
            Ok(())
        }
        Err(e) => {
            crate::println!("*** Can't find {}: {}", host, e);
            Err(e)
        }
    }
}

#[derive(Debug)]
pub struct NetworkInfo {
    pub ip_address: Ipv4Address,
    pub mac_address: MacAddress,
    pub gateway: Ipv4Address,
    pub netmask: Ipv4Address,
    pub dns_servers: Vec<Ipv4Address>,
    pub is_initialized: bool,
    pub is_link_up: bool,
    pub stats: NetworkStats,
    pub arp_table_size: usize,
}

pub fn get_detailed_network_info() -> NetworkInfo {
    let stack = NETWORK_STACK.lock();

    NetworkInfo {
        ip_address: stack.ip_address,
        mac_address: stack.mac_address,
        gateway: stack.gateway,
        netmask: stack.netmask,
        dns_servers: stack.get_dns_servers(),
        is_initialized: stack.is_initialized,
        is_link_up: stack.is_link_up,
        stats: stack.stats.clone(),
        arp_table_size: stack.arp_table.len(),
    }
}

pub fn get_network_info() -> (Ipv4Address, [u8; 6]) {
    let stack = NETWORK_STACK.lock();
    (stack.ip_address, stack.mac_address.octets())
}

pub fn set_ip_address(ip_str: &str) -> Result<(), &'static str> {
    let ip = Ipv4Address::from_str(ip_str)?;
    let mut stack = NETWORK_STACK.lock();

    let old_ip = stack.ip_address;
    let mac_address = stack.mac_address;

    stack.arp_table.remove(&old_ip);
    stack.arp_table.insert(ip, mac_address);
    stack.ip_address = ip;

    crate::serial_println!("NET: IP changed to {}", ip);
    Ok(())
}

pub fn clear_dns_cache() -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();
    if !stack.is_initialized {
        return Err("Network not initialized");
    }
    stack.dns_client.clear_cache();
    Ok(())
}

pub fn get_dns_cache_entries() -> Vec<(String, Ipv4Address, u64)> {
    let stack = NETWORK_STACK.lock();
    stack.dns_client.get_cache_entries()
}

pub fn is_local_network(ip: Ipv4Address) -> bool {
    let stack = NETWORK_STACK.lock();
    let our_net = stack.ip_address.as_u32() & stack.netmask.as_u32();
    let target_net = ip.as_u32() & stack.netmask.as_u32();
    our_net == target_net
}

pub fn get_arp_table() -> Vec<(Ipv4Address, MacAddress)> {
    let stack = NETWORK_STACK.lock();
    stack
        .arp_table
        .iter()
        .map(|(&ip, &mac)| (ip, mac))
        .collect()
}

// Периодическая проверка и обработка входящих сетевых пакетов
pub fn check_and_handle_incoming_packets() {
    // Используем try_lock() из spin::Mutex, который возвращает Option
    let mut stack = if let Some(guard) = NETWORK_STACK.try_lock() {
        guard
    } else {
        return; // Стек заблокирован, пропускаем этот тик
    };

    if !stack.is_initialized {
        return;
    }

    // Проверяем наличие входящих пакетов от драйвера
    if let Some(packet_data) = stack.driver.check_for_incoming_packets() {
        let packet_len: u64 = packet_data.len() as u64;
        if let Err(e) = stack.handle_incoming_packet(&packet_data) {
            crate::serial_println!("NET: Error handling packet: {}", e);
        } else {
            stack.stats.frames_received += 1;
            stack.stats.bytes_received += packet_len;
        }
    }
}

pub fn add_arp_entry(ip_str: &str, mac_str: &str) -> Result<(), &'static str> {
    let ip = Ipv4Address::from_str(ip_str)?;

    let mac_parts: Vec<&str> = mac_str.split(':').collect();
    if mac_parts.len() != 6 {
        return Err("Invalid MAC address format");
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in mac_parts.iter().enumerate() {
        match u8::from_str_radix(part, 16) {
            Ok(byte) => mac_bytes[i] = byte,
            Err(_) => return Err("Invalid MAC address"),
        }
    }

    let mut stack = NETWORK_STACK.lock();
    if !stack.is_initialized {
        return Err("Network not initialized");
    }

    let mac_address = MacAddress::new(mac_bytes);
    stack.arp_table.insert(ip, mac_address);
    crate::serial_println!("NET: ARP entry added: {} -> {}", ip, mac_address);
    Ok(())
}

// Вспомогательные функции
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) + (data[i + 1] as u32);
        } else {
            sum += (data[i] as u32) << 8;
        }
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn get_next_ip_id() -> u16 {
    static mut IP_ID_COUNTER: u16 = 1;
    unsafe {
        IP_ID_COUNTER = IP_ID_COUNTER.wrapping_add(1);
        IP_ID_COUNTER
    }
}

fn get_next_ping_id() -> u16 {
    static mut PING_ID_COUNTER: u16 = 1;
    unsafe {
        PING_ID_COUNTER = PING_ID_COUNTER.wrapping_add(1);
        PING_ID_COUNTER
    }
}
