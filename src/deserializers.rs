use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use unicorn_engine::RegisterARM;
use fault_simulator::prelude::*;

/// Parse hex address strings to u64 values
pub fn parse_hex(s: &str) -> Result<u64, String> {
    let cleaned = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(cleaned, 16)
        .map_err(|e| format!("'{}' is not a valid hex number: {}", s, e))
}

/// Custom deserializer for hex addresses that can handle both strings and numbers
pub fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct HexAddressesVisitor;

    impl<'de> Visitor<'de> for HexAddressesVisitor {
        type Value = Vec<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of hex addresses (strings like \"0x123\" or numbers)")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<u64>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut addresses = Vec::new();

            while let Some(value) = seq.next_element::<serde_json::Value>()? {
                match value {
                    serde_json::Value::String(s) => {
                        let addr = parse_hex(&s).map_err(de::Error::custom)?;
                        addresses.push(addr);
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(addr) = n.as_u64() {
                            addresses.push(addr);
                        } else {
                            return Err(de::Error::custom("Invalid number for address"));
                        }
                    }
                    _ => return Err(de::Error::custom("Address must be a string or number")),
                }
            }

            Ok(addresses)
        }
    }

    deserializer.deserialize_seq(HexAddressesVisitor)
}

/// Convert register name string to RegisterARM enum
fn get_register_from_name(name: &str) -> Option<RegisterARM> {
    match name.to_uppercase().as_str() {
        "R0" => Some(RegisterARM::R0),
        "R1" => Some(RegisterARM::R1),
        "R2" => Some(RegisterARM::R2),
        "R3" => Some(RegisterARM::R3),
        "R4" => Some(RegisterARM::R4),
        "R5" => Some(RegisterARM::R5),
        "R6" => Some(RegisterARM::R6),
        "R7" => Some(RegisterARM::R7),
        "R8" => Some(RegisterARM::R8),
        "R9" => Some(RegisterARM::R9),
        "R10" => Some(RegisterARM::R10),
        "R11" => Some(RegisterARM::R11),
        "R12" => Some(RegisterARM::R12),
        "SP" => Some(RegisterARM::SP),
        "LR" => Some(RegisterARM::LR),
        "PC" => Some(RegisterARM::PC),
        "CPSR" => Some(RegisterARM::CPSR),
        _ => None,
    }
}

/// Custom deserializer for register context that validates register names and handles hex values
pub fn deserialize_register_context<'de, D>(
    deserializer: D,
) -> Result<HashMap<RegisterARM, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct RegisterContextVisitor;

    impl<'de> Visitor<'de> for RegisterContextVisitor {
        type Value = HashMap<RegisterARM, u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of register names to hex values")
        }

        fn visit_map<A>(self, mut map: A) -> Result<HashMap<RegisterARM, u64>, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let mut registers = HashMap::new();

            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                // Validate register name during deserialization
                let register = get_register_from_name(&key).ok_or_else(|| {
                    de::Error::custom(format!("Invalid register name: '{}'", key))
                })?;

                let reg_value = match value {
                    serde_json::Value::String(s) => parse_hex(&s).map_err(de::Error::custom)?,
                    serde_json::Value::Number(n) => {
                        if let Some(val) = n.as_u64() {
                            val
                        } else {
                            return Err(de::Error::custom(format!(
                                "Invalid number for register {}: must be a positive integer",
                                key
                            )));
                        }
                    }
                    _ => {
                        return Err(de::Error::custom(format!(
                            "Register {} value must be a string or number",
                            key
                        )))
                    }
                };

                registers.insert(register, reg_value);
            }

            Ok(registers)
        }
    }

    deserializer.deserialize_map(RegisterContextVisitor)
}

/// Custom deserializer for code patches
pub fn deserialize_code_patches<'de, D>(
    deserializer: D,
) -> Result<Vec<CodePatch>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    struct CodePatchHelper {
        address: String,
        data: String,
        #[serde(default)]
        description: Option<String>, // Allow description field but ignore it
    }

    let patches: Vec<CodePatchHelper> = Deserialize::deserialize(deserializer)?;
    
    patches
        .into_iter()
        .map(|patch| {
            let address = parse_hex(&patch.address).map_err(de::Error::custom)?;
            let hex_val = parse_hex(&patch.data).map_err(de::Error::custom)?;
            
            // Convert u64 to bytes (little-endian, remove leading zeros)
            let mut bytes = Vec::new();
            let mut val = hex_val;
            if val == 0 {
                bytes.push(0);
            } else {
                while val > 0 {
                    bytes.push((val & 0xFF) as u8);
                    val >>= 8;
                }
            }
            
            Ok(CodePatch { address, data: bytes })
        })
        .collect()
}

/// Custom deserializer for memory regions
pub fn deserialize_memory_regions<'de, D>(
    deserializer: D,
) -> Result<Vec<MemoryRegion>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;
    use std::fs;

    #[derive(Deserialize)]
    struct MemoryRegionHelper {
        address: String,
        size: String,
        file: Option<String>, // Optional binary file to load
        #[serde(default)]
        description: Option<String>, // Allow description field but ignore it
    }

    let regions: Vec<MemoryRegionHelper> = Deserialize::deserialize(deserializer)?;
    
    regions
        .into_iter()
        .map(|region| {
            let address = parse_hex(&region.address).map_err(de::Error::custom)?;
            let size = parse_hex(&region.size).map_err(de::Error::custom)?;
            
            // If a file is specified, load its contents
            let data = if let Some(file_path) = region.file {
                Some(fs::read(file_path).map_err(de::Error::custom)?)
            } else {
                None
            };
            
            Ok(MemoryRegion { address, size, data })
        })
        .collect()
}