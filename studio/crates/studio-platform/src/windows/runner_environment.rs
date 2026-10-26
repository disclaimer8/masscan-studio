//! Process-global policy for the dedicated elevated runner only; never call in UI.
use super::Result;
pub fn initialize() -> Result<()> {
    Ok(())
}
