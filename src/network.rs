use crate::dns::DnsClient;
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
    pub dns_queries: u64,
    pub dns_hits: u64,
    pub dns_misses: u64,
    pub dns_cache_entries: u64,
}

// Основная структура сетевого стека
pub struct NetworkStack {
    pub ip_address: Ipv4Address,
    pub mac_address: MacAddress,
    pub gateway: Ipv4Address,
    pub netmask: Ipv4Address,
    pub dns_servers: Vec<Ipv4Address>,
    pub dns_client: DnsClient,
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
            dns_servers: vec![
                Ipv4Address::new(8, 8, 8, 8),        // Google DNS Primary
                Ipv4Address::new(8, 8, 4, 4),        // Google DNS Secondary
                Ipv4Address::new(1, 1, 1, 1),        // Cloudflare DNS
                Ipv4Address::new(208, 67, 222, 222), // OpenDNS
            ],
            dns_client: DnsClient::new(),
            stats: NetworkStats::default(),
            is_initialized: false,
        }
    }

    pub fn set_ip_address(&mut self, ip: Ipv4Address) {
        self.ip_address = ip;
        crate::serial_println!("Network: IP address set to {}", ip);
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

    pub fn get_dns_servers(&self) -> &Vec<Ipv4Address> {
        &self.dns_servers
    }

    pub fn add_dns_server(&mut self, dns_server: Ipv4Address) {
        if !self.dns_servers.contains(&dns_server) {
            self.dns_servers.push(dns_server);
            crate::serial_println!("Network: Added DNS server {}", dns_server);
        }
    }

    pub fn remove_dns_server(&mut self, dns_server: Ipv4Address) {
        self.dns_servers.retain(|&server| server != dns_server);
        crate::serial_println!("Network: Removed DNS server {}", dns_server);
    }

    pub fn is_ip_reachable(&self, target: Ipv4Address) -> bool {
        let our_octets = self.ip_address.octets();
        let target_octets = target.octets();

        // Localhost
        if target_octets[0] == 127 {
            return true;
        }

        // Локальная подсеть (предполагаем /24)
        if our_octets[0] == target_octets[0]
            && our_octets[1] == target_octets[1]
            && our_octets[2] == target_octets[2]
        {
            return true;
        }

        // Публичные адреса (не приватные диапазоны)
        if !is_private_ip(target) {
            return true; // Предполагаем доступность через интернет
        }

        false
    }

    pub fn resolve_domain(&mut self, domain: &str) -> Result<Ipv4Address, &'static str> {
        self.stats.dns_queries += 1;

        // Сначала пытаемся разобрать как IP адрес
        if let Ok(ip) = Ipv4Address::from_str(domain) {
            return Ok(ip);
        }

        crate::serial_println!("DNS: Resolving domain '{}'", domain);

        // Используем реальный DNS клиент
        match self.dns_client.resolve(domain) {
            Ok(ip) => {
                self.stats.dns_hits += 1;
                crate::serial_println!("DNS: Successfully resolved '{}' to {}", domain, ip);
                Ok(ip)
            }
            Err(e) => {
                self.stats.dns_misses += 1;
                crate::serial_println!("DNS: Failed to resolve '{}': {}", domain, e);
                Err(e)
            }
        }
    }

    pub fn clear_dns_cache(&mut self) {
        self.dns_client.clear_cache();
        crate::serial_println!("DNS: Cache cleared");
    }

    pub fn get_dns_cache_entries(&self) -> Vec<(String, Ipv4Address, u64)> {
        self.dns_client.get_cache_entries()
    }

    pub fn get_dns_cache_size(&self) -> usize {
        self.dns_client.get_cache_entries().len()
    }

    pub fn update_stats(&mut self) {
        self.stats.dns_cache_entries = self.get_dns_cache_size() as u64;
    }
}

lazy_static! {
    pub static ref NETWORK_STACK: Mutex<NetworkStack> = Mutex::new(NetworkStack::new());
}

// Инициализация сетевого стека
pub fn init_network() -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    crate::serial_println!("Initializing network stack...");

    // Симулируем инициализацию сетевой карты
    // В реальной реализации здесь был бы код инициализации RTL8139 или другой карты

    stack.is_initialized = true;
    stack.update_stats();

    crate::serial_println!("Network stack initialized successfully");
    crate::serial_println!("Network configuration:");
    crate::serial_println!("  IP: {}", stack.ip_address);
    crate::serial_println!("  MAC: {}", stack.mac_address);
    crate::serial_println!("  Gateway: {}", stack.gateway);
    crate::serial_println!("  DNS servers: {:?}", stack.dns_servers);

    Ok(())
}

// Функция для резолвинга домена или IP
pub fn resolve_host(host: &str) -> Result<(String, Ipv4Address), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    if !stack.is_initialized {
        return Err("Network not initialized");
    }

    match stack.resolve_domain(host) {
        Ok(ip) => {
            let hostname = if host.parse::<Ipv4Address>().is_ok() {
                // Если ввели IP, возвращаем его же как hostname
                host.to_string()
            } else {
                // Если ввели домен, возвращаем домен
                host.to_string()
            };
            Ok((hostname, ip))
        }
        Err(e) => Err(e),
    }
}

// Улучшенная функция ping с поддержкой доменов
pub fn ping(host: &str) -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();

    if !stack.is_initialized {
        return Err("Network not initialized");
    }

    let (hostname, target_ip) = match stack.resolve_domain(host) {
        Ok(ip) => {
            let name = if host.parse::<Ipv4Address>().is_ok() {
                host.to_string()
            } else {
                host.to_string()
            };
            (name, ip)
        }
        Err(e) => return Err(e),
    };

    stack.stats.ping_requests += 1;

    // Симулируем отправку ICMP Echo Request
    if hostname == target_ip.to_string() {
        crate::println!("PING {} 56(84) bytes of data.", target_ip);
    } else {
        crate::println!("PING {} ({}) 56(84) bytes of data.", hostname, target_ip);
    }

    // Проверяем доступность адреса
    if stack.is_ip_reachable(target_ip) {
        // Симулируем успешный ответ
        stack.stats.ping_replies += 1;
        stack.stats.packets_sent += 3;
        stack.stats.packets_received += 3;
        stack.stats.bytes_sent += 192;
        stack.stats.bytes_received += 192;

        // Симулируем разные времена отклика для разных типов адресов
        let (time1, time2, time3) = get_ping_times(target_ip);

        crate::println!(
            "64 bytes from {}: icmp_seq=1 ttl=64 time={}",
            target_ip,
            time1
        );
        crate::println!(
            "64 bytes from {}: icmp_seq=2 ttl=64 time={}",
            target_ip,
            time2
        );
        crate::println!(
            "64 bytes from {}: icmp_seq=3 ttl=64 time={}",
            target_ip,
            time3
        );
        crate::println!();
        crate::println!(
            "--- {} ping statistics ---",
            if hostname == target_ip.to_string() {
                &hostname
            } else {
                &hostname
            }
        );
        crate::println!("3 packets transmitted, 3 received, 0% packet loss");

        let (min_time, avg_time, max_time, mdev_time) = get_ping_stats(target_ip);
        crate::println!(
            "rtt min/avg/max/mdev = {}/{}/{}/{} ms",
            min_time,
            avg_time,
            max_time,
            mdev_time
        );

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
    let mut stack = NETWORK_STACK.lock();
    stack.update_stats();

    NetworkInfo {
        ip_address: stack.ip_address,
        mac_address: stack.mac_address,
        gateway: stack.gateway,
        netmask: stack.netmask,
        dns_servers: stack.dns_servers.clone(),
        is_initialized: stack.is_initialized,
        stats: NetworkStats {
            packets_sent: stack.stats.packets_sent,
            packets_received: stack.stats.packets_received,
            bytes_sent: stack.stats.bytes_sent,
            bytes_received: stack.stats.bytes_received,
            ping_requests: stack.stats.ping_requests,
            ping_replies: stack.stats.ping_replies,
            dns_queries: stack.stats.dns_queries,
            dns_hits: stack.stats.dns_hits,
            dns_misses: stack.stats.dns_misses,
            dns_cache_entries: stack.stats.dns_cache_entries,
        },
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
    pub stats: NetworkStats,
}

// Команда для настройки IP адреса
pub fn set_ip_address(ip_str: &str) -> Result<(), &'static str> {
    let ip = Ipv4Address::from_str(ip_str)?;
    let mut stack = NETWORK_STACK.lock();
    stack.set_ip_address(ip);
    Ok(())
}

// Команда для добавления DNS сервера
pub fn add_dns_server(ip_str: &str) -> Result<(), &'static str> {
    let ip = Ipv4Address::from_str(ip_str)?;
    let mut stack = NETWORK_STACK.lock();
    stack.add_dns_server(ip);
    Ok(())
}

// Команда для удаления DNS сервера
pub fn remove_dns_server(ip_str: &str) -> Result<(), &'static str> {
    let ip = Ipv4Address::from_str(ip_str)?;
    let mut stack = NETWORK_STACK.lock();
    stack.remove_dns_server(ip);
    Ok(())
}

// Функция nslookup
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

// Новые функции для работы с DNS кэшем
pub fn clear_dns_cache() -> Result<(), &'static str> {
    let mut stack = NETWORK_STACK.lock();
    if !stack.is_initialized {
        return Err("Network not initialized");
    }
    stack.clear_dns_cache();
    Ok(())
}

pub fn get_dns_cache_entries() -> Vec<(String, Ipv4Address, u64)> {
    let stack = NETWORK_STACK.lock();
    stack.get_dns_cache_entries()
}

pub fn get_dns_cache_stats() -> (usize, u64, u64, u64) {
    let stack = NETWORK_STACK.lock();
    (
        stack.get_dns_cache_size(),
        stack.stats.dns_queries,
        stack.stats.dns_hits,
        stack.stats.dns_misses,
    )
}

// Команда для просмотра DNS серверов
pub fn list_dns_servers() -> Vec<Ipv4Address> {
    let stack = NETWORK_STACK.lock();
    stack.dns_servers.clone()
}

// Вспомогательные функции
fn is_private_ip(ip: Ipv4Address) -> bool {
    let octets = ip.octets();
    match octets[0] {
        10 => true,
        172 if octets[1] >= 16 && octets[1] <= 31 => true,
        192 if octets[1] == 168 => true,
        127 => true, // Localhost
        _ => false,
    }
}

fn get_ping_times(ip: Ipv4Address) -> (&'static str, &'static str, &'static str) {
    let octets = ip.octets();
    if octets[0] == 127 {
        // Localhost - очень быстро
        ("0.043ms", "0.039ms", "0.041ms")
    } else if is_private_ip(ip) {
        // Локальная сеть - быстро
        ("0.123ms", "0.145ms", "0.134ms")
    } else {
        // Интернет - медленнее, варьируется в зависимости от "расстояния"
        match octets[0] {
            8 => ("8.5ms", "9.2ms", "7.8ms"),            // Google
            1 => ("12.1ms", "11.8ms", "12.5ms"),         // Cloudflare
            142 | 172 => ("15.2ms", "14.8ms", "16.1ms"), // US серверы
            151 => ("22.3ms", "21.9ms", "23.1ms"),       // Europe
            _ => ("25.4ms", "28.1ms", "24.7ms"),         // Остальные
        }
    }
}

fn get_ping_stats(ip: Ipv4Address) -> (&'static str, &'static str, &'static str, &'static str) {
    let octets = ip.octets();
    if octets[0] == 127 {
        ("0.039", "0.041", "0.043", "0.002")
    } else if is_private_ip(ip) {
        ("0.123", "0.134", "0.145", "0.009")
    } else {
        match octets[0] {
            8 => ("7.8", "8.5", "9.2", "0.6"),
            1 => ("11.8", "12.1", "12.5", "0.3"),
            142 | 172 => ("14.8", "15.4", "16.1", "0.5"),
            151 => ("21.9", "22.4", "23.1", "0.5"),
            _ => ("24.7", "26.1", "28.1", "1.4"),
        }
    }
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
        crate::serial_println!(
            "RTL8139: MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac_address[0],
            self.mac_address[1],
            self.mac_address[2],
            self.mac_address[3],
            self.mac_address[4],
            self.mac_address[5]
        );
        Ok(())
    }

    pub fn get_mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn send_packet(&self, _data: &[u8]) -> Result<(), &'static str> {
        if !self.initialized {
            return Err("Network card not initialized");
        }
        // В реальной реализации здесь была бы отправка пакета
        crate::serial_println!("RTL8139: Packet sent (simulated)");
        Ok(())
    }

    pub fn receive_packet(&self) -> Option<Vec<u8>> {
        if !self.initialized {
            return None;
        }
        // В реальной реализации здесь было бы чтение буфера приема
        None
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

// Статистика сетевого интерфейса
pub fn get_interface_stats() -> InterfaceStats {
    let stack = NETWORK_STACK.lock();
    let driver = RTL8139_DRIVER.lock();

    InterfaceStats {
        is_up: stack.is_initialized && driver.is_initialized(),
        ip_address: stack.ip_address,
        mac_address: stack.mac_address,
        packets_sent: stack.stats.packets_sent,
        packets_received: stack.stats.packets_received,
        bytes_sent: stack.stats.bytes_sent,
        bytes_received: stack.stats.bytes_received,
    }
}

#[derive(Debug)]
pub struct InterfaceStats {
    pub is_up: bool,
    pub ip_address: Ipv4Address,
    pub mac_address: MacAddress,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
