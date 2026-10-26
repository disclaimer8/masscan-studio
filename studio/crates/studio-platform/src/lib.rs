#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(target_os = "macos")]
pub mod macos;
pub mod network;
pub mod trusted;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod unix;
