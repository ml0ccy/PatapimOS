use core::fmt;
use lazy_static::lazy_static;
use spin::Mutex;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    const fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

pub struct Writer {
    column_position: usize,
    color_code: ColorCode,
    buffer: &'static mut Buffer,
}

impl Writer {
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            byte => {
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }

                let row = BUFFER_HEIGHT - 1;
                let col = self.column_position;

                let color_code = self.color_code;
                self.buffer.chars[row][col] = ScreenChar {
                    ascii_character: byte,
                    color_code,
                };
                self.column_position += 1;
            }
        }
    }

    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                // Расширенный диапазон ASCII и улучшенная обработка UTF-8
                0x20..=0x7e | b'\n' => self.write_byte(byte),
                // Для non-ASCII символов пытаемся найти подходящую замену
                _ => {
                    // Проверяем, является ли это частью UTF-8 последовательности
                    if byte & 0x80 != 0 {
                        // Это UTF-8, заменяем на знак вопроса вместо квадрата
                        self.write_byte(b'?');
                    } else {
                        // Обычный non-printable ASCII, заменяем на точку
                        self.write_byte(b'.');
                    }
                }
            }
        }
    }

    fn new_line(&mut self) {
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                let character = self.buffer.chars[row][col];
                self.buffer.chars[row - 1][col] = character;
            }
        }
        self.clear_row(BUFFER_HEIGHT - 1);
        self.column_position = 0;
    }

    pub fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };
        for col in 0..BUFFER_WIDTH {
            self.buffer.chars[row][col] = blank;
        }
    }

    pub fn delete_byte(&mut self) {
        if self.column_position > 0 {
            self.column_position -= 1;
            let row = BUFFER_HEIGHT - 1;
            let col = self.column_position;

            let blank = ScreenChar {
                ascii_character: b' ',
                color_code: self.color_code,
            };
            self.buffer.chars[row][col] = blank;
        }
    }

    pub fn write_colored(&mut self, text: &str, color: Color) {
        let old_color = self.color_code;
        self.color_code = ColorCode::new(color, Color::Black);
        self.write_string(text);
        self.color_code = old_color;
    }

    pub fn set_color(&mut self, foreground: Color, background: Color) {
        self.color_code = ColorCode::new(foreground, background);
    }

    pub fn reset_color(&mut self) {
        self.color_code = ColorCode::new(Color::Yellow, Color::Black);
    }

    // Добавляем метод для получения текущей позиции курсора
    pub fn get_cursor_position(&self) -> (usize, usize) {
        (BUFFER_HEIGHT - 1, self.column_position)
    }

    // Добавляем метод для установки позиции курсора
    pub fn set_cursor_position(&mut self, row: usize, col: usize) {
        if row < BUFFER_HEIGHT && col < BUFFER_WIDTH {
            self.column_position = col;
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

lazy_static! {
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer {
        column_position: 0,
        color_code: ColorCode::new(Color::Yellow, Color::Black),
        buffer: unsafe { &mut *(0xb8000 as *mut Buffer) },
    });
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::vga_buffer::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    WRITER.lock().write_fmt(args).unwrap();
}

pub fn clear_screen() {
    let mut writer = WRITER.lock();
    for row in 0..BUFFER_HEIGHT {
        writer.clear_row(row);
    }
    writer.column_position = 0;
}

pub fn delete_byte() {
    let mut writer = WRITER.lock();
    writer.delete_byte();
}

pub fn write_colored_text(text: &str, color: Color) {
    let mut writer = WRITER.lock();
    writer.write_colored(text, color);
}

pub fn set_text_color(foreground: Color, background: Color) {
    let mut writer = WRITER.lock();
    writer.set_color(foreground, background);
}

pub fn reset_text_color() {
    let mut writer = WRITER.lock();
    writer.reset_color();
}

// Улучшенная функция для получения цвета по имени с поддержкой большего количества вариантов
pub fn get_color_enum(name: &str) -> Option<Color> {
    match name.to_lowercase().as_str() {
        "black" => Some(Color::Black),
        "blue" | "darkblue" => Some(Color::Blue),
        "green" | "darkgreen" => Some(Color::Green),
        "cyan" | "darkcyan" => Some(Color::Cyan),
        "red" | "darkred" => Some(Color::Red),
        "magenta" | "darkmagenta" | "purple" => Some(Color::Magenta),
        "brown" | "darkyellow" => Some(Color::Brown),
        "lightgray" | "gray" | "grey" | "lightgrey" => Some(Color::LightGray),
        "darkgray" | "darkgrey" => Some(Color::DarkGray),
        "lightblue" => Some(Color::LightBlue),
        "lightgreen" => Some(Color::LightGreen),
        "lightcyan" => Some(Color::LightCyan),
        "lightred" => Some(Color::LightRed),
        "pink" | "lightmagenta" => Some(Color::Pink),
        "yellow" => Some(Color::Yellow),
        "white" => Some(Color::White),
        _ => None,
    }
}

// Добавляем функции для работы с курсором
pub fn get_cursor_position() -> (usize, usize) {
    let writer = WRITER.lock();
    writer.get_cursor_position()
}

pub fn set_cursor_position(row: usize, col: usize) {
    let mut writer = WRITER.lock();
    writer.set_cursor_position(row, col);
}
