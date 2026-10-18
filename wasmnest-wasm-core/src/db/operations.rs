//! Database operations

use super::{Database, Setting};
use crate::Result;
use chrono::{DateTime, Utc};

/// Helper function to parse datetime from string, with proper error handling for rusqlite
fn parse_datetime_sql(s: &str, field_name: &str) -> std::result::Result<DateTime<Utc>, rusqlite::Error> {
    s.parse()
        .map_err(|e| rusqlite::Error::InvalidParameterName(format!("Invalid datetime for {}: {}", field_name, e)))
}

impl Database {
    // ==================== Settings ====================

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let value = self
            .conn()
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                rusqlite::params![key],
                |row| row.get(0),
            )
            .ok();
        Ok(value)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![key, value, now],
        )?;
        Ok(())
    }

    pub fn get_all_settings(&self) -> Result<Vec<Setting>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT key, value, updated_at FROM settings ORDER BY key")?;

        let settings = stmt
            .query_map([], |row| {
                Ok(Setting {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    updated_at: parse_datetime_sql(&row.get::<_, String>(2)?, "updated_at")?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(settings)
    }
}
