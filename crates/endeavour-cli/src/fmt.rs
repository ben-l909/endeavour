//! Formatting utilities for CLI output including colors, tables, and semantic text styling.

use std::ffi::OsString;

use owo_colors::OwoColorize;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Brand and semantic palette definitions from CLI standards.
pub mod palette {
    /// Amber color: RGB(212, 160, 74) - primary brand color.
    pub const AMBER: (u8, u8, u8) = (212, 160, 74);
    /// ANSI 256 color code for amber.
    pub const AMBER_ANSI256: u8 = 179;
    /// Slate color: RGB(110, 136, 152) - neutral secondary color.
    pub const SLATE: (u8, u8, u8) = (110, 136, 152);
    /// ANSI 256 color code for slate.
    pub const SLATE_ANSI256: u8 = 66;
    /// Teal color: RGB(74, 158, 142) - accent color.
    pub const TEAL: (u8, u8, u8) = (74, 158, 142);
    /// ANSI 256 color code for teal.
    pub const TEAL_ANSI256: u8 = 72;

    /// Vermillion color: RGB(212, 91, 78) - error/alert color.
    pub const VERMILLION: (u8, u8, u8) = (212, 91, 78);
    /// ANSI 256 color code for vermillion.
    pub const VERMILLION_ANSI256: u8 = 167;
    /// Copper color: RGB(212, 138, 74) - warning color.
    pub const COPPER: (u8, u8, u8) = (212, 138, 74);
    /// ANSI 256 color code for copper.
    pub const COPPER_ANSI256: u8 = 173;
    /// Sage color: RGB(91, 158, 107) - success color.
    pub const SAGE: (u8, u8, u8) = (91, 158, 107);
    /// ANSI 256 color code for sage.
    pub const SAGE_ANSI256: u8 = 71;
    /// Steel color: RGB(91, 143, 212) - info color.
    pub const STEEL: (u8, u8, u8) = (91, 143, 212);
    /// ANSI 256 color code for steel.
    pub const STEEL_ANSI256: u8 = 68;
    /// Ash color: RGB(120, 120, 120) - dark neutral.
    pub const ASH: (u8, u8, u8) = (120, 120, 120);
    /// ANSI 256 color code for ash.
    pub const ASH_ANSI256: u8 = 243;

    /// Chalk color: RGB(200, 200, 200) - light neutral.
    pub const CHALK: (u8, u8, u8) = (200, 200, 200);
    /// ANSI 256 color code for chalk.
    pub const CHALK_ANSI256: u8 = 251;
    /// Dim color: RGB(90, 90, 90) - muted text.
    pub const DIM: (u8, u8, u8) = (90, 90, 90);
    /// ANSI 256 color code for dim.
    pub const DIM_ANSI256: u8 = 240;
    /// Faint color: RGB(58, 58, 58) - very muted text.
    pub const FAINT: (u8, u8, u8) = (58, 58, 58);
    /// ANSI 256 color code for faint.
    pub const FAINT_ANSI256: u8 = 236;
}

/// Horizontal text alignment for table cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// Status indicator for semantic output (pass, fail, warn, info).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Info,
}

/// Visual weight of separator lines (heavy, standard, light).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    Heavy,
    Standard,
    Light,
}

/// A column definition for table rendering with title, width, and alignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    title: String,
    width: usize,
    align: Align,
}

impl Column {
    /// Creates a new column with fixed visible width and alignment.
    pub fn new(title: impl Into<String>, width: usize, align: Align) -> Self {
        Self {
            title: title.into(),
            width,
            align,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
    indent: usize,
}

impl Table {
    /// Creates a standard table with a one-space left indent.
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            indent: 1,
        }
    }

    /// Overrides left indentation spaces.
    pub fn with_indent(mut self, indent: usize) -> Self {
        self.indent = indent;
        self
    }

    /// Appends a row. Missing cells are rendered empty.
    pub fn add_row<T: Into<String>>(&mut self, row: Vec<T>) {
        self.rows.push(row.into_iter().map(Into::into).collect());
    }

    /// Renders the complete table including header and separator row.
    pub fn render(&self) -> String {
        let indent = " ".repeat(self.indent);
        let sep = style("│", palette::DIM, false);
        let header_sep = style("┼", palette::DIM, false);
        let mut lines = Vec::with_capacity(self.rows.len() + 2);

        let header_cells = self
            .columns
            .iter()
            .map(|column| {
                let text = fit_cell(&column.title, column.width, Align::Left);
                format!(" {} ", style(&text, palette::CHALK, true))
            })
            .collect::<Vec<_>>();
        lines.push(format!(
            "{indent}{}",
            header_cells.join(&format!(" {sep} "))
        ));

        let rule_cells = self
            .columns
            .iter()
            .map(|column| "─".repeat(column.width + 2))
            .collect::<Vec<_>>();
        lines.push(format!("{indent}{}", rule_cells.join(&header_sep)));

        for row in &self.rows {
            let row_cells = self
                .columns
                .iter()
                .enumerate()
                .map(|(index, column)| {
                    let value = row.get(index).map(String::as_str).unwrap_or("");
                    let text = fit_cell(value, column.width, column.align);
                    format!(" {} ", style(&text, palette::CHALK, false))
                })
                .collect::<Vec<_>>();
            lines.push(format!("{indent}{}", row_cells.join(&format!(" {sep} "))));
        }

        lines.join("\n")
    }
}

/// Semantic error text.
pub fn error(text: impl AsRef<str>) -> String {
    style(text.as_ref(), palette::VERMILLION, true)
}

/// Semantic warning text.
pub fn warning(text: impl AsRef<str>) -> String {
    style(text.as_ref(), palette::COPPER, true)
}

/// Semantic success text.
pub fn success(text: impl AsRef<str>) -> String {
    style(text.as_ref(), palette::SAGE, true)
}

/// Semantic informational text.
pub fn info(text: impl AsRef<str>) -> String {
    style(text.as_ref(), palette::STEEL, true)
}

/// Formats an address with standards-compliant lowercase hex and zero padding.
pub fn format_addr(addr: u64) -> String {
    if addr <= u32::MAX as u64 {
        format!("0x{addr:08x}")
    } else {
        format!("0x{addr:016x}")
    }
}

/// Formats and colors an address as bold teal.
pub fn format_addr_styled(addr: u64) -> String {
    style(&format_addr(addr), palette::TEAL, true)
}

/// Returns a 4-character status badge wrapped in square brackets.
pub fn status_badge(status: Status) -> String {
    let (label, color) = match status {
        Status::Pass => ("PASS", palette::SAGE),
        Status::Fail => ("FAIL", palette::VERMILLION),
        Status::Warn => ("WARN", palette::COPPER),
        Status::Info => ("INFO", palette::STEEL),
    };

    style(&format!("[{label}]"), color, true)
}

/// Renders an H1 section header with the brand mark and heavy separator.
pub fn h1(title: impl AsRef<str>, width: usize) -> String {
    let heading = style(&format!("◆ {}", title.as_ref()), palette::AMBER, true);
    let rule = separator(Separator::Heavy, width);
    format!("{heading}\n{rule}")
}

/// Renders an H2 section header.
pub fn h2(title: impl AsRef<str>) -> String {
    style(title.as_ref(), palette::CHALK, true)
}

/// Renders an H3 minor heading in uppercase dim text.
pub fn h3(title: impl AsRef<str>) -> String {
    style(&title.as_ref().to_ascii_uppercase(), palette::DIM, false)
}

/// Renders a full-width separator line in the configured weight.
pub fn separator(weight: Separator, width: usize) -> String {
    let (glyph, color) = match weight {
        Separator::Heavy => ('═', palette::SLATE),
        Separator::Standard => ('─', palette::DIM),
        Separator::Light => ('┄', palette::FAINT),
    };
    let line = std::iter::repeat_n(glyph, width.max(1)).collect::<String>();
    style(&line, color, false)
}

fn style(text: &str, color: (u8, u8, u8), bold: bool) -> String {
    if !colors_enabled() {
        return text.to_string();
    }

    if bold {
        text.truecolor(color.0, color.1, color.2).bold().to_string()
    } else {
        text.truecolor(color.0, color.1, color.2).to_string()
    }
}

fn colors_enabled() -> bool {
    colors_enabled_with(std::env::var_os("NO_COLOR"))
}

fn colors_enabled_with(no_color_env: Option<OsString>) -> bool {
    no_color_env.is_none()
}

fn fit_cell(value: &str, width: usize, align: Align) -> String {
    let truncated = truncate_with_ellipsis(value, width);
    let visible = visible_width(&truncated);
    let pad = width.saturating_sub(visible);

    match align {
        Align::Left => format!("{truncated}{}", " ".repeat(pad)),
        Align::Right => format!("{}{truncated}", " ".repeat(pad)),
    }
}

fn truncate_with_ellipsis(value: &str, width: usize) -> String {
    let visible = strip_ansi(value);
    if visible_width(&visible) <= width {
        return visible;
    }

    if width == 0 {
        return String::new();
    }

    if width == 1 {
        return "…".to_string();
    }

    let mut out = String::new();
    let mut current = 0;
    for ch in visible.chars() {
        let Some(ch_width) = UnicodeWidthChar::width(ch) else {
            continue;
        };
        if current + ch_width + 1 > width {
            break;
        }
        current += ch_width;
        out.push(ch);
    }
    out.push('…');
    out
}

fn visible_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            let _ = chars.next();
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{
        colors_enabled_with, format_addr, h1, separator, status_badge, strip_ansi, Align, Column,
        Separator, Status, Table,
    };

    #[test]
    fn formats_32_bit_addresses() {
        assert_eq!(format_addr(0x1234), "0x00001234");
    }

    #[test]
    fn formats_64_bit_addresses() {
        assert_eq!(format_addr(0x1_0000_3f40), "0x0000000100003f40");
    }

    #[test]
    fn status_badges_are_fixed_width_tags() {
        let pass = strip_ansi(&status_badge(Status::Pass));
        let fail = strip_ansi(&status_badge(Status::Fail));
        let warn = strip_ansi(&status_badge(Status::Warn));
        let info = strip_ansi(&status_badge(Status::Info));

        assert_eq!(pass, "[PASS]");
        assert_eq!(fail, "[FAIL]");
        assert_eq!(warn, "[WARN]");
        assert_eq!(info, "[INFO]");
    }

    #[test]
    fn table_renders_with_alignment_and_truncation() {
        let mut table = Table::new(vec![
            Column::new("Address", 12, Align::Left),
            Column::new("Size", 5, Align::Right),
            Column::new("Name", 8, Align::Left),
        ]);
        table.add_row(vec!["0x00401000", "142", "decrypt_payload"]);

        let rendered = strip_ansi(&table.render());

        assert!(rendered.contains("Address"));
        assert!(rendered.contains("142"));
        assert!(rendered.contains("│"));
        assert!(rendered.contains("decrypt…"));
    }

    #[test]
    fn separators_and_headers_match_shapes() {
        assert_eq!(strip_ansi(&separator(Separator::Heavy, 5)), "═════");
        assert_eq!(strip_ansi(&separator(Separator::Standard, 5)), "─────");
        assert_eq!(strip_ansi(&separator(Separator::Light, 5)), "┄┄┄┄┄");

        let heading = strip_ansi(&h1("Session", 8));
        assert_eq!(heading, "◆ Session\n════════");
    }

    #[test]
    fn no_color_disables_color_output() {
        assert!(colors_enabled_with(None));
        assert!(!colors_enabled_with(Some("1".into())));
    }
}
