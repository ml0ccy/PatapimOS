//! Полноценный DNS клиент с реальными UDP запросами
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

// DNS константы
const DNS_PORT: u16 = 53;
const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_LABEL_SIZE: usize = 63;
const DNS_QUERY_TIMEOUT: u32 = 5000; // 5 секунд в миллисекундах

// DNS типы записей
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsRecordType {
    A = 1,     // IPv4 адрес
    NS = 2,    // Name Server
    CNAME = 5, // Canonical Name
    PTR = 12,  // Pointer
    MX = 15,   // Mail Exchange
    AAAA = 28, // IPv6 адрес
}

// DNS заголовок
#[derive(Debug)]
struct DnsHeader {
    id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authority: u16,
    additional: u16,
}

impl DnsHeader {
    fn new_query(id: u16) -> Self {
        DnsHeader {
            id,
            flags: 0x0100, // Standard query, recursion desired
            questions: 1,
            answers: 0,
            authority: 0,
            additional: 0,
        }
    }

    fn to_bytes(&self) -> [u8; DNS_HEADER_SIZE] {
        let mut bytes = [0u8; DNS_HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.questions.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.answers.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.authority.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.additional.to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < DNS_HEADER_SIZE {
            return Err("DNS header too short");
        }

        Ok(DnsHeader {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            questions: u16::from_be_bytes([bytes[4], bytes[5]]),
            answers: u16::from_be_bytes([bytes[6], bytes[7]]),
            authority: u16::from_be_bytes([bytes[8], bytes[9]]),
            additional: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    fn response_code(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
}

// DNS вопрос
#[derive(Debug)]
struct DnsQuestion {
    name: String,
    record_type: DnsRecordType,
    class: u16, // 1 для Internet
}

impl DnsQuestion {
    fn new(name: String, record_type: DnsRecordType) -> Self {
        DnsQuestion {
            name,
            record_type,
            class: 1, // Internet class
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Кодируем доменное имя в DNS формате
        for label in self.name.split('.') {
            if label.len() > DNS_MAX_LABEL_SIZE || label.is_empty() {
                continue;
            }
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // Завершающий нуль

        // Добавляем тип записи и класс
        bytes.extend_from_slice(&(self.record_type as u16).to_be_bytes());
        bytes.extend_from_slice(&self.class.to_be_bytes());

        bytes
    }
}

// DNS ответ
#[derive(Debug)]
struct DnsAnswer {
    name: String,
    record_type: DnsRecordType,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

impl DnsAnswer {
    fn get_ipv4(&self) -> Option<crate::network::Ipv4Address> {
        if self.record_type == DnsRecordType::A && self.data.len() == 4 {
            Some(crate::network::Ipv4Address::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }

    fn get_cname(&self) -> Option<String> {
        if self.record_type == DnsRecordType::CNAME {
            // Парсим доменное имя из данных
            self.parse_domain_name(&self.data, 0)
                .ok()
                .map(|(name, _)| name)
        } else {
            None
        }
    }

    fn parse_domain_name(
        &self,
        data: &[u8],
        mut offset: usize,
    ) -> Result<(String, usize), &'static str> {
        let mut name = String::new();
        let original_offset = offset;
        let mut jumps = 0;

        loop {
            if offset >= data.len() {
                return Err("Offset beyond data");
            }

            let length = data[offset];

            if length == 0 {
                offset += 1;
                break;
            }

            // Проверяем сжатие имен
            if (length & 0xC0) == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err("Compressed name offset out of bounds");
                }

                let pointer = ((length & 0x3F) as u16) << 8 | data[offset + 1] as u16;
                offset = pointer as usize;
                jumps += 1;

                if jumps > 10 {
                    return Err("Too many compression jumps");
                }
                continue;
            }

            offset += 1;

            if offset + length as usize > data.len() {
                return Err("Label extends beyond data");
            }

            if !name.is_empty() {
                name.push('.');
            }

            let label = core::str::from_utf8(&data[offset..offset + length as usize])
                .map_err(|_| "Invalid UTF-8 in domain name")?;
            name.push_str(label);
            offset += length as usize;
        }

        Ok((
            name,
            if jumps > 0 {
                original_offset + 2
            } else {
                offset
            },
        ))
    }
}

// DNS пакет
#[derive(Debug)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsAnswer>,
}

impl DnsPacket {
    fn new_query(domain: &str, record_type: DnsRecordType) -> Self {
        let id = get_dns_query_id();
        let header = DnsHeader::new_query(id);
        let question = DnsQuestion::new(domain.to_string(), record_type);

        DnsPacket {
            header,
            questions: vec![question],
            answers: Vec::new(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Добавляем заголовок
        bytes.extend_from_slice(&self.header.to_bytes());

        // Добавляем вопросы
        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }

        bytes
    }

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < DNS_HEADER_SIZE {
            return Err("DNS packet too short");
        }

        let header = DnsHeader::from_bytes(&data[0..DNS_HEADER_SIZE])?;
        let mut offset = DNS_HEADER_SIZE;

        // Пропускаем вопросы (мы их знаем)
        for _ in 0..header.questions {
            offset = Self::skip_question(data, offset)?;
        }

        // Парсим ответы
        let mut answers = Vec::new();
        for _ in 0..header.answers {
            let (answer, new_offset) = Self::parse_answer(data, offset)?;
            answers.push(answer);
            offset = new_offset;
        }

        Ok(DnsPacket {
            header,
            questions: Vec::new(), // Не парсим вопросы обратно
            answers,
        })
    }

    fn skip_question(data: &[u8], mut offset: usize) -> Result<usize, &'static str> {
        // Пропускаем доменное имя
        while offset < data.len() {
            let length = data[offset];
            if length == 0 {
                offset += 1;
                break;
            }

            if (length & 0xC0) == 0xC0 {
                offset += 2; // Сжатое имя
                break;
            }

            offset += 1 + length as usize;
        }

        // Пропускаем тип и класс (4 байта)
        offset += 4;

        if offset > data.len() {
            return Err("Question extends beyond packet");
        }

        Ok(offset)
    }

    fn parse_answer(data: &[u8], mut offset: usize) -> Result<(DnsAnswer, usize), &'static str> {
        // Парсим имя
        let (name, new_offset) = Self::parse_name(data, offset)?;
        offset = new_offset;

        if offset + 10 > data.len() {
            return Err("Answer record too short");
        }

        // Парсим тип, класс, TTL, длину данных
        let record_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let data_length = u16::from_be_bytes([data[offset + 8], data[offset + 9]]);

        offset += 10;

        if offset + data_length as usize > data.len() {
            return Err("Answer data extends beyond packet");
        }

        let answer_data = data[offset..offset + data_length as usize].to_vec();
        offset += data_length as usize;

        let record_type_enum = match record_type {
            1 => DnsRecordType::A,
            2 => DnsRecordType::NS,
            5 => DnsRecordType::CNAME,
            12 => DnsRecordType::PTR,
            15 => DnsRecordType::MX,
            28 => DnsRecordType::AAAA,
            _ => DnsRecordType::A,
        };

        let answer = DnsAnswer {
            name,
            record_type: record_type_enum,
            class,
            ttl,
            data: answer_data,
        };

        Ok((answer, offset))
    }

    fn parse_name(data: &[u8], mut offset: usize) -> Result<(String, usize), &'static str> {
        let mut name = String::new();
        let mut original_offset = offset;
        let mut jumped = false;
        let mut jumps = 0;

        loop {
            if offset >= data.len() {
                return Err("Name extends beyond packet");
            }

            let length = data[offset];

            if length == 0 {
                if !jumped {
                    offset += 1;
                }
                break;
            }

            if (length & 0xC0) == 0xC0 {
                if !jumped {
                    original_offset = offset + 2;
                    jumped = true;
                }

                if offset + 1 >= data.len() {
                    return Err("Compressed pointer out of bounds");
                }

                let pointer = ((length & 0x3F) as u16) << 8 | data[offset + 1] as u16;
                offset = pointer as usize;
                jumps += 1;

                if jumps > 10 {
                    return Err("Too many compression jumps");
                }
                continue;
            }

            offset += 1;

            if offset + length as usize > data.len() {
                return Err("Label extends beyond packet");
            }

            if !name.is_empty() {
                name.push('.');
            }

            let label = core::str::from_utf8(&data[offset..offset + length as usize])
                .map_err(|_| "Invalid UTF-8 in domain name")?;
            name.push_str(label);
            offset += length as usize;
        }

        Ok((name, if jumped { original_offset } else { offset }))
    }
}

// Глобальный реестр ожидаемых ответов
static PENDING_QUERIES: Mutex<BTreeMap<u16, (String, DnsRecordType)>> = Mutex::new(BTreeMap::new());
static QUERY_RESPONSES: Mutex<BTreeMap<u16, Result<crate::network::Ipv4Address, &'static str>>> =
    Mutex::new(BTreeMap::new());

// DNS клиент
pub struct DnsClient {
    cache: BTreeMap<String, (crate::network::Ipv4Address, u64, u32)>, // (IP, expire_time, TTL)
    query_id_counter: u16,
    queries_sent: u64,
    responses_received: u64,
    cache_hits: u64,
    cache_misses: u64,
    timeouts: u64,
    errors: u64,
}

impl DnsClient {
    pub fn new() -> Self {
        DnsClient {
            cache: BTreeMap::new(),
            query_id_counter: 1,
            queries_sent: 0,
            responses_received: 0,
            cache_hits: 0,
            cache_misses: 0,
            timeouts: 0,
            errors: 0,
        }
    }

    pub fn resolve(&mut self, domain: &str) -> Result<crate::network::Ipv4Address, &'static str> {
        // Проверяем кэш
        if let Some((ip, expire_time, _ttl)) = self.cache.get(domain) {
            let current_time = get_current_time();
            if *expire_time > current_time {
                self.cache_hits += 1;
                crate::serial_println!("DNS: Cache hit for {} -> {}", domain, ip);
                return Ok(*ip);
            } else {
                self.cache.remove(domain);
            }
        }

        self.cache_misses += 1;
        crate::serial_println!("DNS: Resolving {}", domain);

        // Получаем DNS серверы
        let dns_servers = vec![
            crate::network::Ipv4Address::new(8, 8, 8, 8), // Google DNS
            crate::network::Ipv4Address::new(1, 1, 1, 1), // Cloudflare DNS
            crate::network::Ipv4Address::new(208, 67, 222, 222), // OpenDNS
        ];

        // Пробуем каждый DNS сервер
        for dns_server in dns_servers {
            crate::serial_println!("DNS: Querying {} for {}", dns_server, domain);

            match self.send_dns_query(dns_server, domain, DnsRecordType::A) {
                Ok(ip) => {
                    // Кэшируем результат
                    let expire_time = get_current_time() + 300; // 5 минут
                    self.cache
                        .insert(domain.to_string(), (ip, expire_time, 300));

                    crate::serial_println!("DNS: Resolved {} to {} via {}", domain, ip, dns_server);
                    return Ok(ip);
                }
                Err(e) => {
                    crate::serial_println!("DNS: Query to {} failed: {}", dns_server, e);
                    continue;
                }
            }
        }

        self.errors += 1;
        Err("All DNS servers failed")
    }

    fn send_dns_query(
        &mut self,
        dns_server: crate::network::Ipv4Address,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Result<crate::network::Ipv4Address, &'static str> {
        // Создаем DNS запрос
        let dns_packet = DnsPacket::new_query(domain, record_type);
        let query_id = dns_packet.header.id;
        let dns_data = dns_packet.to_bytes();

        crate::serial_println!(
            "DNS: Sending {} byte query to {}",
            dns_data.len(),
            dns_server
        );

        // Регистрируем ожидаемый ответ
        {
            let mut pending = PENDING_QUERIES.lock();
            pending.insert(query_id, (domain.to_string(), record_type));
        }

        // Отправляем UDP пакет
        let src_port = 32768 + (self.query_id_counter % 32768);

        {
            let mut stack = crate::network::NETWORK_STACK.lock();
            if !stack.is_initialized {
                return Err("Network not initialized");
            }

            // Создаем UDP пакет
            if let Err(e) = self.send_udp_dns_query(&mut stack, dns_server, src_port, dns_data) {
                return Err(e);
            }
        }

        self.queries_sent += 1;
        self.query_id_counter = self.query_id_counter.wrapping_add(1);

        // Ожидаем ответ
        self.wait_for_response(query_id, DNS_QUERY_TIMEOUT)
    }

    fn send_udp_dns_query(
        &self,
        stack: &mut crate::network::NetworkStack,
        dns_server: crate::network::Ipv4Address,
        src_port: u16,
        dns_data: Vec<u8>,
    ) -> Result<(), &'static str> {
        // Создаем UDP заголовок
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&src_port.to_be_bytes()); // Source port
        udp_packet.extend_from_slice(&DNS_PORT.to_be_bytes()); // Destination port
        let udp_length = 8 + dns_data.len();
        udp_packet.extend_from_slice(&(udp_length as u16).to_be_bytes()); // Length
        udp_packet.extend_from_slice(&[0, 0]); // Checksum (0 for now)
        udp_packet.extend_from_slice(&dns_data); // DNS data

        // Создаем IP заголовок
        let mut ip_packet = Vec::new();
        ip_packet.push(0x45); // Version 4, IHL 5
        ip_packet.push(0); // Type of Service
        let total_length = 20 + udp_packet.len();
        ip_packet.extend_from_slice(&(total_length as u16).to_be_bytes());
        ip_packet.extend_from_slice(&get_ip_id().to_be_bytes()); // ID
        ip_packet.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags + Fragment offset
        ip_packet.push(64); // TTL
        ip_packet.push(17); // Protocol (UDP)
        ip_packet.extend_from_slice(&[0, 0]); // Header checksum (calculate later)
        ip_packet.extend_from_slice(&stack.ip_address.octets()); // Source IP
        ip_packet.extend_from_slice(&dns_server.octets()); // Destination IP

        // Вычисляем IP checksum
        let checksum = calculate_ip_checksum(&ip_packet);
        ip_packet[10] = (checksum >> 8) as u8;
        ip_packet[11] = checksum as u8;

        // Добавляем UDP payload
        ip_packet.extend_from_slice(&udp_packet);

        // Определяем MAC назначения
        let dst_mac = if stack.is_same_network(dns_server) {
            stack.get_mac_for_ip(dns_server)
        } else {
            stack.get_mac_for_ip(stack.gateway)
        };

        // Создаем Ethernet кадр
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac.octets());
        frame.extend_from_slice(&stack.mac_address.octets());
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        frame.extend_from_slice(&ip_packet);

        // Padding
        while frame.len() < 64 {
            frame.push(0);
        }

        // Отправляем через драйвер
        stack.driver.send_raw_packet(&frame)?;

        crate::serial_println!("DNS: UDP query sent to {}", dns_server);
        Ok(())
    }

    fn wait_for_response(
        &mut self,
        query_id: u16,
        timeout_ms: u32,
    ) -> Result<crate::network::Ipv4Address, &'static str> {
        let _start_time = get_current_time();
        let timeout_ticks = timeout_ms as u64 / 10; // Приблизительно

        // Ожидаем ответ
        for _ in 0..timeout_ticks {
            {
                let mut responses = QUERY_RESPONSES.lock();
                if let Some(result) = responses.remove(&query_id) {
                    // Убираем из ожидающих
                    let mut pending = PENDING_QUERIES.lock();
                    pending.remove(&query_id);

                    self.responses_received += 1;
                    return result.map_err(|_e| {
                        self.errors += 1;
                        "DNS query failed"
                    });
                }
            }

            // Небольшая задержка
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        // Таймаут
        {
            let mut pending = PENDING_QUERIES.lock();
            pending.remove(&query_id);
        }

        self.timeouts += 1;
        crate::serial_println!("DNS: Query timeout for ID {}", query_id);
        Err("DNS query timeout")
    }

    // Обработчик входящих DNS ответов (вызывается из сетевого драйвера)
    pub fn handle_dns_response(data: &[u8]) -> Result<(), &'static str> {
        let packet = DnsPacket::from_bytes(data)?;

        if !packet.header.is_response() {
            return Err("Not a DNS response");
        }

        let query_id = packet.header.id;
        crate::serial_println!("DNS: Received response for query ID {}", query_id);

        // Проверяем, ожидаем ли мы этот ответ
        let expected_domain = {
            let pending = PENDING_QUERIES.lock();
            pending.get(&query_id).map(|(domain, _)| domain.clone())
        };

        let expected_domain = match expected_domain {
            Some(domain) => domain,
            None => {
                crate::serial_println!("DNS: Unexpected response ID {}", query_id);
                return Err("Unexpected DNS response");
            }
        };

        // Обрабатываем ответы
        let result = if packet.header.response_code() != 0 {
            "DNS server error"
        } else if packet.answers.is_empty() {
            "No DNS answers"
        } else {
            // Ищем A-запись
            for answer in &packet.answers {
                match answer.record_type {
                    DnsRecordType::A => {
                        if let Some(ip) = answer.get_ipv4() {
                            crate::serial_println!(
                                "DNS: Found A record: {} -> {}",
                                expected_domain,
                                ip
                            );
                            return Self::store_response(query_id, Ok(ip));
                        }
                    }
                    DnsRecordType::CNAME => {
                        if let Some(cname) = answer.get_cname() {
                            crate::serial_println!(
                                "DNS: Found CNAME: {} -> {}",
                                expected_domain,
                                cname
                            );
                            // Для CNAME нужен дополнительный запрос, пока пропускаем
                        }
                    }
                    _ => {
                        crate::serial_println!(
                            "DNS: Skipping record type {:?}",
                            answer.record_type
                        );
                    }
                }
            }
            "No usable A records found"
        };

        Self::store_response(query_id, Err(result))
    }

    fn store_response(
        query_id: u16,
        result: Result<crate::network::Ipv4Address, &'static str>,
    ) -> Result<(), &'static str> {
        let mut responses = QUERY_RESPONSES.lock();
        responses.insert(query_id, result);
        Ok(())
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
        crate::serial_println!("DNS: Cache cleared");
    }

    pub fn get_cache_entries(&self) -> Vec<(String, crate::network::Ipv4Address, u64)> {
        self.cache
            .iter()
            .map(|(domain, (ip, expire, _ttl))| (domain.clone(), *ip, *expire))
            .collect()
    }
}

// Вспомогательные функции
fn get_dns_query_id() -> u16 {
    static mut COUNTER: u16 = 1;
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER
    }
}

fn get_ip_id() -> u16 {
    static mut COUNTER: u16 = 1;
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER
    }
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;

    for i in (0..header.len()).step_by(2) {
        if i + 1 < header.len() {
            sum += ((header[i] as u32) << 8) + (header[i + 1] as u32);
        } else {
            sum += (header[i] as u32) << 8;
        }
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn get_current_time() -> u64 {
    static mut TIME: u64 = 0;
    unsafe {
        TIME += 1;
        TIME
    }
}
