#![forbid(unsafe_code)]
//! Порт ядра masscan (AGPL-3.0). Источник: masscan © Robert David Graham,
//! github.com/robertdavidgraham/masscan, HEAD 8e6b3b0.

pub mod blackrock;
pub mod checksum;
pub mod config;
pub mod cookie;
pub mod massip;
pub mod packet;
pub mod probe;
pub mod ranges;
pub mod scan;
pub mod targets;
pub mod throttle;

/// Версия masscan, с которой сверяется порт.
pub const ORACLE_MASSCAN_VERSION: &str = "1.3.9-integration";

#[cfg(test)]
mod tests {
    #[test]
    fn version_constant_matches_oracle() {
        assert_eq!(super::ORACLE_MASSCAN_VERSION, "1.3.9-integration");
    }
}
