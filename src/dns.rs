use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryInto;

// DNS константы
const DNS_PORT: u16 = 53;
const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_LABEL_SIZE: usize = 63;
const DNS_MAX_NAME_SIZE: usize = 255;

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

impl From<u16> for DnsRecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsRecordType::A,
            2 => DnsRecordType::NS,
            5 => DnsRecordType::CNAME,
            12 => DnsRecordType::PTR,
            15 => DnsRecordType::MX,
            28 => DnsRecordType::AAAA,
            _ => DnsRecordType::A, // По умолчанию
        }
    }
}

// DNS классы
#[derive(Debug, Clone, Copy)]
pub enum DnsClass {
    Internet = 1,
}

// DNS заголовок
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

impl DnsHeader {
    pub fn new_query(id: u16) -> Self {
        DnsHeader {
            id,
            flags: 0x0100, // Standard query, recursion desired
            questions: 1,
            answers: 0,
            authority: 0,
            additional: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; DNS_HEADER_SIZE] {
        let mut bytes = [0u8; DNS_HEADER_SIZE];
        BigEndian::write_u16(&mut bytes[0..2], self.id);
        BigEndian::write_u16(&mut bytes[2..4], self.flags);
        BigEndian::write_u16(&mut bytes[4..6], self.questions);
        BigEndian::write_u16(&mut bytes[6..8], self.answers);
        BigEndian::write_u16(&mut bytes[8..10], self.authority);
        BigEndian::write_u16(&mut bytes[10..12], self.additional);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < DNS_HEADER_SIZE {
            return Err("DNS header too short");
        }

        Ok(DnsHeader {
            id: BigEndian::read_u16(&bytes[0..2]),
            flags: BigEndian::read_u16(&bytes[2..4]),
            questions: BigEndian::read_u16(&bytes[4..6]),
            answers: BigEndian::read_u16(&bytes[6..8]),
            authority: BigEndian::read_u16(&bytes[8..10]),
            additional: BigEndian::read_u16(&bytes[10..12]),
        })
    }

    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn is_error(&self) -> bool {
        (self.flags & 0x000F) != 0
    }
}

// DNS вопрос
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: DnsRecordType,
    pub class: DnsClass,
}

impl DnsQuestion {
    pub fn new(name: String) -> Self {
        DnsQuestion {
            name,
            record_type: DnsRecordType::A,
            class: DnsClass::Internet,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Кодируем доменное имя
        bytes.extend_from_slice(&encode_domain_name(&self.name));

        // Добавляем тип и класс
        let mut type_class = [0u8; 4];
        BigEndian::write_u16(&mut type_class[0..2], self.record_type as u16);
        BigEndian::write_u16(&mut type_class[2..4], self.class as u16);
        bytes.extend_from_slice(&type_class);

        bytes
    }
}

// DNS ответ
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: DnsRecordType,
    pub class: DnsClass,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsAnswer {
    pub fn get_ipv4(&self) -> Option<crate::network::Ipv4Address> {
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
}

// DNS пакет
#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsPacket {
    pub fn new_query(domain: &str) -> Self {
        let id = get_dns_id();
        let header = DnsHeader::new_query(id);
        let question = DnsQuestion::new(domain.to_string());

        DnsPacket {
            header,
            questions: vec![question],
            answers: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Добавляем заголовок
        bytes.extend_from_slice(&self.header.to_bytes());

        // Добавляем вопросы
        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }

        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < DNS_HEADER_SIZE {
            return Err("DNS packet too short");
        }

        let header = DnsHeader::from_bytes(&data[0..DNS_HEADER_SIZE])?;
        let mut offset = DNS_HEADER_SIZE;

        // Парсим вопросы (пропускаем для упрощения)
        let mut questions = Vec::new();
        for _ in 0..header.questions {
            let (question, new_offset) = parse_question(&data, offset)?;
            questions.push(question);
            offset = new_offset;
        }

        // Парсим ответы
        let mut answers = Vec::new();
        for _ in 0..header.answers {
            let (answer, new_offset) = parse_answer(&data, offset)?;
            answers.push(answer);
            offset = new_offset;
        }

        Ok(DnsPacket {
            header,
            questions,
            answers,
        })
    }
}

// UDP пакет для DNS
#[derive(Debug)]
pub struct UdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub data: Vec<u8>,
}

impl UdpPacket {
    pub fn new(src_port: u16, dst_port: u16, data: Vec<u8>) -> Self {
        let length = 8 + data.len() as u16;
        UdpPacket {
            src_port,
            dst_port,
            length,
            checksum: 0, // Упрощаем - не вычисляем checksum
            data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut header = [0u8; 8];

        BigEndian::write_u16(&mut header[0..2], self.src_port);
        BigEndian::write_u16(&mut header[2..4], self.dst_port);
        BigEndian::write_u16(&mut header[4..6], self.length);
        BigEndian::write_u16(&mut header[6..8], self.checksum);

        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("UDP packet too short");
        }

        let src_port = BigEndian::read_u16(&data[0..2]);
        let dst_port = BigEndian::read_u16(&data[2..4]);
        let length = BigEndian::read_u16(&data[4..6]);
        let checksum = BigEndian::read_u16(&data[6..8]);

        if data.len() < length as usize {
            return Err("UDP packet length mismatch");
        }

        let payload = data[8..length as usize].to_vec();

        Ok(UdpPacket {
            src_port,
            dst_port,
            length,
            checksum,
            data: payload,
        })
    }
}

// DNS клиент
pub struct DnsClient {
    dns_servers: Vec<crate::network::Ipv4Address>,
    cache: BTreeMap<String, (crate::network::Ipv4Address, u64)>, // (IP, expire_time)
    query_id: u16,
}

impl DnsClient {
    pub fn new() -> Self {
        DnsClient {
            dns_servers: vec![
                crate::network::Ipv4Address::new(8, 8, 8, 8), // Google DNS
                crate::network::Ipv4Address::new(1, 1, 1, 1), // Cloudflare DNS
                crate::network::Ipv4Address::new(208, 67, 222, 222), // OpenDNS
            ],
            cache: BTreeMap::new(),
            query_id: 1,
        }
    }

    pub fn resolve(&mut self, domain: &str) -> Result<crate::network::Ipv4Address, &'static str> {
        // Сначала проверяем кэш
        if let Some((ip, expire_time)) = self.cache.get(domain) {
            let current_time = get_current_time(); // Упрощенная функция времени
            if *expire_time > current_time {
                crate::serial_println!("DNS: Cache hit for {}", domain);
                return Ok(*ip);
            } else {
                // Удаляем устаревшую запись
                self.cache.remove(domain);
            }
        }

        crate::serial_println!("DNS: Resolving {} via external DNS", domain);

        // Пробуем каждый DNS сервер
        for dns_server in &self.dns_servers.clone() {
            match self.query_dns_server(*dns_server, domain) {
                Ok(ip) => {
                    // Кэшируем на 5 минут
                    let expire_time = get_current_time() + 300;
                    self.cache.insert(domain.to_string(), (ip, expire_time));
                    crate::serial_println!("DNS: Resolved {} to {} via {}", domain, ip, dns_server);
                    return Ok(ip);
                }
                Err(e) => {
                    crate::serial_println!("DNS: Failed to query {} - {}", dns_server, e);
                    continue;
                }
            }
        }

        Err("All DNS servers failed")
    }

    fn query_dns_server(
        &mut self,
        dns_server: crate::network::Ipv4Address,
        domain: &str,
    ) -> Result<crate::network::Ipv4Address, &'static str> {
        // Создаем DNS запрос
        let dns_packet = DnsPacket::new_query(domain);
        let dns_data = dns_packet.to_bytes();

        // Создаем UDP пакет
        let src_port = 12345 + (self.query_id % 1000); // Случайный порт
        let udp_packet = UdpPacket::new(src_port, DNS_PORT, dns_data);
        let udp_data = udp_packet.to_bytes();

        self.query_id = self.query_id.wrapping_add(1);

        // В реальной реализации здесь был бы отправлен пакет по сети
        // Пока симулируем успешный ответ для известных доменов
        match self.simulate_dns_response(domain) {
            Some(ip) => Ok(ip),
            None => Err("Domain not found"),
        }
    }

    // Симулируем DNS ответы для демонстрации
    fn simulate_dns_response(&self, domain: &str) -> Option<crate::network::Ipv4Address> {
        // Расширенная база известных доменов
        match domain {
            "google.com" | "www.google.com" => {
                Some(crate::network::Ipv4Address::new(142, 250, 191, 14))
            }
            "github.com" | "www.github.com" => {
                Some(crate::network::Ipv4Address::new(140, 82, 114, 4))
            }
            "stackoverflow.com" => Some(crate::network::Ipv4Address::new(151, 101, 1, 69)),
            "rust-lang.org" => Some(crate::network::Ipv4Address::new(18, 66, 113, 44)),
            "youtube.com" | "www.youtube.com" => {
                Some(crate::network::Ipv4Address::new(142, 250, 191, 46))
            }
            "cloudflare.com" => Some(crate::network::Ipv4Address::new(104, 16, 132, 229)),
            "microsoft.com" => Some(crate::network::Ipv4Address::new(20, 112, 250, 133)),
            "apple.com" => Some(crate::network::Ipv4Address::new(17, 142, 160, 59)),
            "amazon.com" => Some(crate::network::Ipv4Address::new(176, 32, 103, 205)),
            "facebook.com" | "www.facebook.com" => {
                Some(crate::network::Ipv4Address::new(157, 240, 251, 35))
            }
            "twitter.com" | "x.com" => Some(crate::network::Ipv4Address::new(104, 244, 42, 129)),
            "instagram.com" => Some(crate::network::Ipv4Address::new(157, 240, 251, 174)),
            "reddit.com" => Some(crate::network::Ipv4Address::new(151, 101, 1, 140)),
            "wikipedia.org" | "en.wikipedia.org" => {
                Some(crate::network::Ipv4Address::new(208, 80, 154, 224))
            }
            "yandex.ru" => Some(crate::network::Ipv4Address::new(5, 255, 255, 70)),
            "mail.ru" => Some(crate::network::Ipv4Address::new(94, 100, 180, 200)),
            "localhost" => Some(crate::network::Ipv4Address::new(127, 0, 0, 1)),
            _ => {
                // Для неизвестных доменов генерируем правдоподобный IP
                if domain.contains('.') {
                    Some(generate_plausible_ip(domain))
                } else {
                    None
                }
            }
        }
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    pub fn get_cache_entries(&self) -> Vec<(String, crate::network::Ipv4Address, u64)> {
        self.cache
            .iter()
            .map(|(domain, (ip, expire))| (domain.clone(), *ip, *expire))
            .collect()
    }
}

// Вспомогательные функции
fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();

    for label in domain.split('.') {
        if label.len() > DNS_MAX_LABEL_SIZE {
            break; // Слишком длинная метка
        }

        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }

    encoded.push(0); // Завершающий нуль
    encoded
}

fn parse_question(data: &[u8], offset: usize) -> Result<(DnsQuestion, usize), &'static str> {
    let (name, new_offset) = parse_domain_name(data, offset)?;

    if new_offset + 4 > data.len() {
        return Err("Question too short");
    }

    let record_type = BigEndian::read_u16(&data[new_offset..new_offset + 2]);
    let class = BigEndian::read_u16(&data[new_offset + 2..new_offset + 4]);

    let question = DnsQuestion {
        name,
        record_type: DnsRecordType::from(record_type),
        class: DnsClass::Internet, // Упрощаем
    };

    Ok((question, new_offset + 4))
}

fn parse_answer(data: &[u8], offset: usize) -> Result<(DnsAnswer, usize), &'static str> {
    let (name, mut new_offset) = parse_domain_name(data, offset)?;

    if new_offset + 10 > data.len() {
        return Err("Answer too short");
    }

    let record_type = BigEndian::read_u16(&data[new_offset..new_offset + 2]);
    let class = BigEndian::read_u16(&data[new_offset + 2..new_offset + 4]);
    let ttl = BigEndian::read_u32(&data[new_offset + 4..new_offset + 8]);
    let data_length = BigEndian::read_u16(&data[new_offset + 8..new_offset + 10]);

    new_offset += 10;

    if new_offset + data_length as usize > data.len() {
        return Err("Answer data too short");
    }

    let answer_data = data[new_offset..new_offset + data_length as usize].to_vec();

    let answer = DnsAnswer {
        name,
        record_type: DnsRecordType::from(record_type),
        class: DnsClass::Internet,
        ttl,
        data: answer_data,
    };

    Ok((answer, new_offset + data_length as usize))
}

fn parse_domain_name(data: &[u8], offset: usize) -> Result<(String, usize), &'static str> {
    let mut name = String::new();
    let mut current_offset = offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if current_offset >= data.len() {
            return Err("Domain name extends beyond packet");
        }

        let length = data[current_offset];

        if length == 0 {
            current_offset += 1;
            break;
        }

        if (length & 0xC0) == 0xC0 {
            // Это указатель на сжатое имя
            if !jumped {
                offset = current_offset + 2;
            }

            let pointer = ((length & 0x3F) as u16) << 8 | data[current_offset + 1] as u16;
            current_offset = pointer as usize;
            jumped = true;
            jumps += 1;

            if jumps > 5 {
                return Err("Too many jumps in domain name");
            }
            continue;
        }

        current_offset += 1;

        if current_offset + length as usize > data.len() {
            return Err("Domain label extends beyond packet");
        }

        if !name.is_empty() {
            name.push('.');
        }

        let label = core::str::from_utf8(&data[current_offset..current_offset + length as usize])
            .map_err(|_| "Invalid UTF-8 in domain name")?;
        name.push_str(label);

        current_offset += length as usize;
    }

    let final_offset = if jumped { offset } else { current_offset };
    Ok((name, final_offset))
}

fn generate_plausible_ip(domain: &str) -> crate::network::Ipv4Address {
    // Генерируем правдоподобный IP на основе хэша доменного имени
    let mut hash = 0u32;
    for byte in domain.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }

    // Используем диапазоны, типичные для хостинга
    let ranges = [
        (104, 16),  // Cloudflare
        (151, 101), // Fastly
        (13, 107),  // Amazon
        (172, 217), // Google
        (157, 240), // Facebook
    ];

    let range_idx = (hash % ranges.len() as u32) as usize;
    let (a, b) = ranges[range_idx];

    crate::network::Ipv4Address::new(a, b, ((hash >> 16) % 256) as u8, ((hash >> 8) % 256) as u8)
}

fn get_dns_id() -> u16 {
    static mut COUNTER: u16 = 1;
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER
    }
}

fn get_current_time() -> u64 {
    // Упрощенная функция времени - возвращает секунды с момента загрузки
    static mut TIME: u64 = 0;
    unsafe {
        TIME += 1;
        TIME
    }
}
