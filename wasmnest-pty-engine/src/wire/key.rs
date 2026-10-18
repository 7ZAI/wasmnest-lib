//! 按键组合线协议（原宿主 `enums/special_key.rs`，票 01 收编为单一事实源）
//!
//! 动态按键组合解析系统 — 替代原硬编码 SpecialKey enum
//! 支持所有键盘修饰键组合：Ctrl/Shift/Alt + 字母/数字/功能键/方向键
//! 通过 ANSI 转义序列和 ASCII 控制字符规则动态计算 PTY 字节
//!
//! **wire 面**：[`KeyCombo`] 序列化为组合字符串（`"ctrl+a"`），是
//! [`crate::wire::TerminalAction::Input`] 的 `special_key` 字段形状；
//! **引擎面**：[`KeyCombo::to_pty_bytes`] 仍被宿主 PTY 写入路径调用
//! （`pty/pty_process.rs::send_special_key`），故随类型一并收编，宿主侧零改动。

use serde::{Deserialize, Serialize};

// ==================== Modifiers ====================

/// 修饰键位标志
const MOD_CTRL: u8 = 0x01;
const MOD_SHIFT: u8 = 0x02;
const MOD_ALT: u8 = 0x04;

// ==================== KeyCode ====================

/// 键名
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCode {
    /// 字母 a-z 或数字 0-9 或空格
    Char(char),
    /// 方向键
    Up,
    Down,
    Left,
    Right,
    /// 编辑键
    Tab,
    Enter,
    Escape,
    Backspace,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    /// 功能键 F1~F12
    F(u8),
}

impl KeyCode {
    /// 从字符串解析键名
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "up" => Some(KeyCode::Up),
            "down" => Some(KeyCode::Down),
            "left" => Some(KeyCode::Left),
            "right" => Some(KeyCode::Right),
            "tab" => Some(KeyCode::Tab),
            "enter" => Some(KeyCode::Enter),
            "escape" | "esc" => Some(KeyCode::Escape),
            "backspace" | "del" => Some(KeyCode::Backspace),
            "delete" => Some(KeyCode::Delete),
            "home" => Some(KeyCode::Home),
            "end" => Some(KeyCode::End),
            "pageup" | "page_up" => Some(KeyCode::PageUp),
            "pagedown" | "page_down" => Some(KeyCode::PageDown),
            "insert" => Some(KeyCode::Insert),
            "space" => Some(KeyCode::Char(' ')),
            _ => {
                // F1~F12
                if let Some(rest) = s.strip_prefix('f').or_else(|| s.strip_prefix('F')) {
                    if let Ok(n) = rest.parse::<u8>() {
                        if (1..=12).contains(&n) {
                            return Some(KeyCode::F(n));
                        }
                    }
                }
                // 单字母
                let chars: Vec<char> = s.chars().collect();
                if chars.len() == 1 {
                    let c = chars[0];
                    if c.is_ascii_lowercase() || c.is_ascii_digit() {
                        return Some(KeyCode::Char(c));
                    }
                    // 大写字母转小写
                    if c.is_ascii_uppercase() {
                        return Some(KeyCode::Char(c.to_ascii_lowercase()));
                    }
                }
                None
            }
        }
    }

    /// 序列化为字符串
    fn to_str(&self) -> String {
        match self {
            KeyCode::Char(c) => c.to_string(),
            KeyCode::Up => "up".to_string(),
            KeyCode::Down => "down".to_string(),
            KeyCode::Left => "left".to_string(),
            KeyCode::Right => "right".to_string(),
            KeyCode::Tab => "tab".to_string(),
            KeyCode::Enter => "enter".to_string(),
            KeyCode::Escape => "escape".to_string(),
            KeyCode::Backspace => "backspace".to_string(),
            KeyCode::Delete => "delete".to_string(),
            KeyCode::Home => "home".to_string(),
            KeyCode::End => "end".to_string(),
            KeyCode::PageUp => "pageup".to_string(),
            KeyCode::PageDown => "pagedown".to_string(),
            KeyCode::Insert => "insert".to_string(),
            KeyCode::F(n) => format!("f{}", n),
        }
    }
}

// ==================== KeyCombo ====================

/// 按键组合 = 修饰键 + 键名
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCombo {
    /// 修饰键位标志
    modifiers: u8,
    /// 键名
    pub key: KeyCode,
}

impl KeyCombo {
    /// 创建新的按键组合
    pub fn new(modifiers: u8, key: KeyCode) -> Self {
        Self { modifiers, key }
    }

    /// 是否包含 Ctrl 修饰键
    pub fn ctrl(&self) -> bool {
        self.modifiers & MOD_CTRL != 0
    }

    /// 是否包含 Shift 修饰键
    pub fn shift(&self) -> bool {
        self.modifiers & MOD_SHIFT != 0
    }

    /// 是否包含 Alt 修饰键
    pub fn alt(&self) -> bool {
        self.modifiers & MOD_ALT != 0
    }

    /// 获取修饰键标志
    pub fn modifiers(&self) -> u8 {
        self.modifiers
    }

    /// 解析按键组合字符串
    ///
    /// 格式：`"ctrl+a"`、`"shift+up"`、`"ctrl+shift+f1"`、`"alt+f"`（+ 分隔）
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        // 优先尝试新格式（用 + 分隔）
        let parts: Vec<&str> = s.split('+').collect();
        if parts.len() > 1 {
            // 最后一个部分是键名，前面都是修饰键
            let key_str = parts.last()?;
            let key = KeyCode::from_str(key_str)?;

            let mut modifiers: u8 = 0;
            for &part in &parts[..parts.len() - 1] {
                match part.to_lowercase().as_str() {
                    "ctrl" | "control" => modifiers |= MOD_CTRL,
                    "shift" => modifiers |= MOD_SHIFT,
                    "alt" | "meta" => modifiers |= MOD_ALT,
                    _ => return None,
                }
            }
            return Some(KeyCombo { modifiers, key });
        }

        // 无修饰键
        let key = KeyCode::from_str(s)?;
        Some(KeyCombo { modifiers: 0, key })
    }

    /// 计算修饰键编号（xterm 修饰键协议）
    ///
    /// Shift=2, Alt=3, Alt+Shift=4, Ctrl=5, Ctrl+Shift=6, Ctrl+Alt=7, Ctrl+Alt+Shift=8
    /// 无修饰键返回 None
    fn modifier_number(&self) -> Option<u8> {
        match (self.ctrl(), self.shift(), self.alt()) {
            (false, true, false) => Some(2),
            (false, false, true) => Some(3),
            (false, true, true) => Some(4),
            (true, false, false) => Some(5),
            (true, true, false) => Some(6),
            (true, false, true) => Some(7),
            (true, true, true) => Some(8),
            (false, false, false) => None,
        }
    }

    /// 计算对应的 PTY 字节序列
    ///
    /// 根据按键组合动态生成 ANSI 转义序列或 ASCII 控制字符
    pub fn to_pty_bytes(&self) -> Option<Vec<u8>> {
        match &self.key {
            // ==================== Ctrl + 字母/数字 ====================
            KeyCode::Char(c) if self.ctrl() && !self.shift() && !self.alt() => self.ctrl_char_bytes(*c),

            // ==================== Alt + 字母 ====================
            KeyCode::Char(c) if self.alt() && !self.ctrl() && !self.shift() => {
                // Alt+字母 = ESC + 字母
                let mut bytes = vec![0x1b];
                bytes.push(*c as u8);
                Some(bytes)
            }

            // ==================== Alt + Shift + 字母 ====================
            KeyCode::Char(c) if self.alt() && self.shift() && !self.ctrl() => {
                // Alt+Shift+字母 = ESC + 大写字母
                let mut bytes = vec![0x1b];
                bytes.push(c.to_ascii_uppercase() as u8);
                Some(bytes)
            }

            // ==================== 方向键（动态修饰键） ====================
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => self.arrow_key_bytes(),

            // ==================== 功能键 F1~F12（动态修饰键） ====================
            KeyCode::F(n) => self.function_key_bytes(*n),

            // ==================== Tab（动态修饰键） ====================
            KeyCode::Tab => self.tab_key_bytes(),

            // ==================== CSI 编辑键（动态修饰键） ====================
            // Delete/Insert/PageUp/PageDown/Home/End 统一走 csi_edit_key_bytes
            KeyCode::Delete | KeyCode::Insert | KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End => {
                self.csi_edit_key_bytes()
            }

            // ==================== ASCII 控制字符编辑键 ====================
            KeyCode::Enter if !self.ctrl() && !self.shift() && !self.alt() => {
                Some(vec![0x0d]) // \r
            }
            KeyCode::Escape if !self.ctrl() && !self.shift() && !self.alt() => {
                Some(vec![0x1b]) // ESC
            }
            KeyCode::Backspace if !self.ctrl() && !self.shift() && !self.alt() => {
                Some(vec![0x7f]) // DEL
            }

            // ==================== 无修饰字母/数字（直接输入字符） ====================
            KeyCode::Char(c) if !self.ctrl() && !self.alt() && !self.shift() => Some(vec![*c as u8]),
            KeyCode::Char(c) if !self.ctrl() && !self.alt() && self.shift() => Some(vec![c.to_ascii_uppercase() as u8]),

            // 其他不支持的组合
            _ => None,
        }
    }

    /// Ctrl + 字母/数字 → ASCII 控制字符
    ///
    /// Ctrl+A~Z → 0x01~0x1A
    /// Ctrl+2 → NUL(0x00), Ctrl+3~7 → 0x1B~0x1F, Ctrl+8 → DEL(0x7F)
    fn ctrl_char_bytes(&self, c: char) -> Option<Vec<u8>> {
        if c.is_ascii_lowercase() {
            // Ctrl+A = 0x01, Ctrl+B = 0x02, ..., Ctrl+Z = 0x1A
            let byte = (c as u8) - b'a' + 1;
            Some(vec![byte])
        } else if c.is_ascii_digit() {
            let byte = match c {
                '2' => 0x00, // NUL
                '3' => 0x1b, // ESC
                '4' => 0x1c, // FS
                '5' => 0x1d, // GS
                '6' => 0x1e, // RS
                '7' => 0x1f, // US
                '8' => 0x7f, // DEL
                _ => return None,
            };
            Some(vec![byte])
        } else if c == ' ' {
            // Ctrl+Space = NUL
            Some(vec![0x00])
        } else {
            None
        }
    }

    /// 方向键 + 修饰键 → ANSI 转义序列
    ///
    /// 无修饰：\x1b[A/B/C/D
    /// 带修饰：\x1b[1;{mod}A/B/C/D
    fn arrow_key_bytes(&self) -> Option<Vec<u8>> {
        let dir = match &self.key {
            KeyCode::Up => 'A',
            KeyCode::Down => 'B',
            KeyCode::Right => 'C',
            KeyCode::Left => 'D',
            _ => return None,
        };

        let bytes = match self.modifier_number() {
            None => format!("\x1b[{}", dir),
            Some(mod_num) => format!("\x1b[1;{}{}", mod_num, dir),
        };

        Some(bytes.into_bytes())
    }

    /// Tab + 修饰键 → ANSI 转义序列
    ///
    /// 无修饰：0x09 (HT)
    /// Shift+Tab：\x1b[Z (SHT，终端传统序列)
    /// 其他修饰：\x1b[1;{mod}I (xterm CHT 序列)
    fn tab_key_bytes(&self) -> Option<Vec<u8>> {
        if !self.ctrl() && !self.shift() && !self.alt() {
            return Some(vec![0x09]); // HT
        }
        // Shift+Tab 传统序列 \x1b[Z（仅无其他修饰键时）
        if self.shift() && !self.ctrl() && !self.alt() {
            return Some("\x1b[Z".as_bytes().to_vec());
        }
        // 其他修饰键组合：\x1b[1;{mod}I
        let mod_num = self.modifier_number()?;
        Some(format!("\x1b[1;{}I", mod_num).into_bytes())
    }

    /// CSI 编辑键 + 修饰键 → ANSI 转义序列
    ///
    /// 统一处理 Delete/Insert/PageUp/PageDown/Home/End 的所有修饰键组合
    ///
    /// CSI~ 格式键（Delete/Insert/PageUp/PageDown）：
    ///   无修饰：\x1b[{n}~
    ///   带修饰：\x1b[{n};{mod}~
    ///
    /// CSI 字母格式键（Home/End）：
    ///   无修饰：\x1b[H / \x1b[F
    ///   带修饰：\x1b[1;{mod}H / \x1b[1;{mod}F
    fn csi_edit_key_bytes(&self) -> Option<Vec<u8>> {
        match &self.key {
            // CSI~ 格式：\x1b[{n}~ 或 \x1b[{n};{mod}~
            KeyCode::Delete => self.csi_tilde_key(3),
            KeyCode::Insert => self.csi_tilde_key(2),
            KeyCode::PageUp => self.csi_tilde_key(5),
            KeyCode::PageDown => self.csi_tilde_key(6),
            // CSI 字母格式：\x1b[{final} 或 \x1b[1;{mod}{final}
            KeyCode::Home => self.csi_letter_key('H'),
            KeyCode::End => self.csi_letter_key('F'),
            _ => None,
        }
    }

    /// CSI~ 格式键：\x1b[{n}~ 或 \x1b[{n};{mod}~
    fn csi_tilde_key(&self, n: u8) -> Option<Vec<u8>> {
        let bytes = match self.modifier_number() {
            None => format!("\x1b[{}~", n),
            Some(mod_num) => format!("\x1b[{};{}~", n, mod_num),
        };
        Some(bytes.into_bytes())
    }

    /// CSI 字母格式键：\x1b[{final} 或 \x1b[1;{mod}{final}
    fn csi_letter_key(&self, final_char: char) -> Option<Vec<u8>> {
        let bytes = match self.modifier_number() {
            None => format!("\x1b[{}", final_char),
            Some(mod_num) => format!("\x1b[1;{}{}", mod_num, final_char),
        };
        Some(bytes.into_bytes())
    }

    /// 功能键 F1~F12 → ANSI 转义序列
    fn function_key_bytes(&self, n: u8) -> Option<Vec<u8>> {
        if !(1..=12).contains(&n) {
            return None;
        }

        // 带修饰键的 F 键
        if let Some(mod_num) = self.modifier_number() {
            // F1~F4 使用 SS3 序列加修饰键
            if (1..=4).contains(&n) {
                let pp = match n {
                    1 => 'P',
                    2 => 'Q',
                    3 => 'R',
                    4 => 'S',
                    _ => return None,
                };
                return Some(format!("\x1b[1;{}{}", mod_num, pp).into_bytes());
            }
            // F5~F12 使用 CSI 序列加修饰键
            let code = match n {
                5 => 15,
                6 => 17,
                7 => 18,
                8 => 19,
                9 => 20,
                10 => 21,
                11 => 23,
                12 => 24,
                _ => return None,
            };
            return Some(format!("\x1b[{};{}~", code, mod_num).into_bytes());
        }

        // 无修饰键
        let bytes = match n {
            1 => "\x1bOP".as_bytes().to_vec(),
            2 => "\x1bOQ".as_bytes().to_vec(),
            3 => "\x1bOR".as_bytes().to_vec(),
            4 => "\x1bOS".as_bytes().to_vec(),
            5 => "\x1b[15~".as_bytes().to_vec(),
            6 => "\x1b[17~".as_bytes().to_vec(),
            7 => "\x1b[18~".as_bytes().to_vec(),
            8 => "\x1b[19~".as_bytes().to_vec(),
            9 => "\x1b[20~".as_bytes().to_vec(),
            10 => "\x1b[21~".as_bytes().to_vec(),
            11 => "\x1b[23~".as_bytes().to_vec(),
            12 => "\x1b[24~".as_bytes().to_vec(),
            _ => return None,
        };
        Some(bytes)
    }

    /// 序列化为字符串
    pub fn to_str(&self) -> String {
        let mut parts = Vec::new();
        if self.ctrl() {
            parts.push("ctrl".to_string());
        }
        if self.shift() {
            parts.push("shift".to_string());
        }
        if self.alt() {
            parts.push("alt".to_string());
        }
        parts.push(self.key.to_str());
        parts.join("+")
    }
}

// ==================== Serde 实现 ====================

/// KeyCombo 序列化为字符串，反序列化从字符串解析
/// 格式："ctrl+a", "shift+up", "enter" 等
impl Serialize for KeyCombo {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_str())
    }
}

impl<'de> Deserialize<'de> for KeyCombo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        KeyCombo::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid key combo: {}", s)))
    }
}

// ==================== 单元测试 ====================

