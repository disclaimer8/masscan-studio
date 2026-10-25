//! The UI may only open the explicit, root-sealed local feth fixture.
pub fn validate_manifest(bytes: &[u8]) -> Result<(), String> {
    let m: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    for (key, value) in [
        ("state", "sealed"),
        ("scanner_if", "feth4201"),
        ("peer_if", "feth4202"),
        ("scanner_mac", "02:ac:00:00:00:01"),
        ("peer_mac", "02:ac:00:00:00:02"),
        ("source_ip", "198.18.0.1"),
        ("peer_ip", "198.18.0.2"),
    ] {
        if m[key].as_str() != Some(value) {
            return Err(format!(
                "Stand manifest {key} does not match the fixed Studio lab profile"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_or_changed_stand_is_not_a_raw_scan_capability() {
        let valid = serde_json::json!({"state":"sealed","scanner_if":"feth4201","peer_if":"feth4202","scanner_mac":"02:ac:00:00:00:01","peer_mac":"02:ac:00:00:00:02","source_ip":"198.18.0.1","peer_ip":"198.18.0.2"});
        assert!(validate_manifest(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for key in [
            "state",
            "scanner_if",
            "peer_if",
            "scanner_mac",
            "peer_mac",
            "source_ip",
            "peer_ip",
        ] {
            let mut bad = valid.clone();
            bad[key] = "changed".into();
            assert!(
                validate_manifest(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "{key}"
            );
        }
        assert!(validate_manifest(b"{}").is_err());
    }
}
