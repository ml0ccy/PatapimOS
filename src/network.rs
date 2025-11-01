use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;

// Простая структура для IPv4 адреса
#[derive(Debug, Clone, Copy, PartialEq)]
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

// Простая структура для MAC адреса
#[derive(Debug, Clone, Copy)]
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

// Сетевые статистики
#[derive(Debug, Default)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub ping_requests: u64,
    pub ping_replies: u64,
}

// Основная структура сетевого стека
pub struct NetworkStack {
    pub ip_address: Ipv4Address,
    pub mac_address: MacAddress,
    pub gateway: Ipv4Address,
    pub netmask: Ipv4Address,
    pub stats: NetworkStats,
    pub is_initialized: bool,
}

impl NetworkStack {
    fn new() -> Self {
        NetworkStack {
            ip_address: Ipv4Address::new(192, 168, 1, 100),
            mac_address: MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            gateway: Ipv4Address::new(192, 168, 1, 1),
            netmask: Ipv4Address::new(255, 255, 255, 0),
            stats: NetworkStats::default(),
            is_initialized: false,
        }
    }

    pub fn set_ip_address(&mut self, ip: Ipv4Address) {
        self.ip_address = ip;
    }

    pub fn get_ip_address(&self) -> Ipv4Address {
        self.ip_address
    }

    pub fn get_mac_address(&self) -> MacAddress {
        self.mac_address
    }

    pub fn get_stats(&self) -> &NetworkStats {
        &self.stats
    }

    pub fn is_ip_reachable(&self, target: Ipv4Address) -> bool {
        // Простая проверка: находится ли адрес в той же подсети
        let our_octets = self.ip_address.octets();
        let target_octets = target.octets();

        // Сравниваем первые 3 октета (подсеть /24)
        our_octets[0] == target_octets[0]
            && our_octets[1] == target_octets[1]
            && our_octets[2] == target_octets[2]
    }
}

lazy_static! {
    pub static ref NETWORK_STACK: Mutex<NetworkStack> = Mutex::new(NetworkStack::new());
}

// Инициализация сетевого стека
pub fn init_network() -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    crate::serial_println!("Initializing virtual network stack...");

    // Симулируем инициализацию сетевой карты
    // В реальной реализации здесь был бы код инициализации RTL8139 или другой карты

    stack.is_initialized = true;
    crate::serial_println!("Network stack initialized");

    Ok(())
}

// Функция ping с симуляцией
pub fn ping(target_ip: Ipv4Address) -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    if !stack.is_initialized {
        return Err("Network not initialized");
    }

    stack.stats.ping_requests += 1;

    // Симулируем отправку ICMP Echo Request
    crate::println!("PING {} ({}) 56(84) bytes of data.", target_ip, target_ip);

    // Проверяем доступность адреса
    if stack.is_ip_reachable(target_ip) {
        // Симулируем успешный ответ
        stack.stats.ping_replies += 1;
        stack.stats.packets_sent += 1;
        stack.stats.packets_received += 1;
        stack.stats.bytes_sent += 64;
        stack.stats.bytes_received += 64;

        crate::println!(
            "64 bytes from {}: icmp_seq=1 ttl=64 time=0.123ms",
            target_ip
        );
        crate::println!(
            "64 bytes from {}: icmp_seq=2 ttl=64 time=0.156ms",
            target_ip
        );
        crate::println!(
            "64 bytes from {}: icmp_seq=3 ttl=64 time=0.142ms",
            target_ip
        );
        crate::println!();
        crate::println!("--- {} ping statistics ---", target_ip);
        crate::println!("3 packets transmitted, 3 received, 0% packet loss");
        crate::println!("rtt min/avg/max/mdev = 0.123/0.140/0.156/0.014 ms");

        Ok(())
    } else {
        crate::println!("ping: connect: Network is unreachable");
        Err("Network unreachable")
    }
}

// Получение информации о сети
pub fn get_network_info() -> (Ipv4Address, [u8; 6]) {
    let stack = NETWORK_STACK.lock();
    (stack.ip_address, stack.mac_address.octets())
}

// Получение расширенной информации о сети
pub fn get_detailed_network_info() -> NetworkInfo {
    let stack = NETWORK_STACK.lock();
    NetworkInfo {
        ip_address: stack.ip_address,
        mac_address: stack.mac_address,
        gateway: stack.gateway,
        netmask: stack.netmask,
        is_initialized: stack.is_initialized,
        stats: NetworkStats {
            packets_sent: stack.stats.packets_sent,
            packets_received: stack.stats.packets_received,
            bytes_sent: stack.stats.bytes_sent,
            bytes_received: stack.stats.bytes_received,
            ping_requests: stack.stats.ping_requests,
            ping_replies: stack.stats.ping_replies,
        },
    }
}

#[derive(Debug)]
pub struct NetworkInfo {
    pub ip_address: Ipv4Address,
    pub mac_address: MacAddress,
    pub gateway: Ipv4Address,
    pub netmask: Ipv4Address,
    pub is_initialized: bool,
    pub stats: NetworkStats,
}

// Команда для настройки IP адреса
pub fn set_ip_address(ip_str: &str) -> Result<(), &'static str> {
    let ip = Ipv4Address::from_str(ip_str)?;
    let mut stack = NETWORK_STACK.lock();
    stack.set_ip_address(ip);
    Ok(())
}

// Базовый RTL8139 драйвер (упрощенная версия)
pub struct RTL8139 {
    io_base: u16,
    mac_address: [u8; 6],
    initialized: bool,
}

impl RTL8139 {
    pub fn new() -> Self {
        RTL8139 {
            io_base: 0,
            mac_address: [0; 6],
            initialized: false,
        }
    }

    pub fn detect_and_init(&mut self) -> Result<(), &'static str> {
        // В реальной реализации здесь был бы код поиска PCI устройства
        // и инициализации RTL8139
        crate::serial_println!("RTL8139: Searching for network card...");

        // Симулируем обнаружение карты
        self.io_base = 0xC000; // Примерный IO base
        self.mac_address = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]; // Виртуальный MAC
        self.initialized = true;

        crate::serial_println!("RTL8139: Virtual network card initialized");
        Ok(())
    }

    pub fn get_mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

lazy_static! {
    pub static ref RTL8139_DRIVER: Mutex<RTL8139> = Mutex::new(RTL8139::new());
}

// Инициализация драйвера
pub fn init_rtl8139() -> Result<(), &'static str> {
    let mut driver = RTL8139_DRIVER.lock();
    driver.detect_and_init()
}
