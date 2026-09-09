use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::Cpu,
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    TraceElement,
};
use std::fmt::Debug;
use std::sync::Arc;

/// Widest instruction the fault can modify. ARM Thumb instructions are 2 or 4 bytes.
const MAX_INSTRUCTION_BYTES: usize = 4;

/// Command bit flip fault structure
///
#[derive(Clone)]
pub struct CmdBitFlip {
    pub xor_value: u32,
}

impl Debug for CmdBitFlip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Command BitFlip (cmdbf_{:08x})", self.xor_value)
    }
}

/// Implementation for CmdBitFlip fault
impl CmdBitFlip {
    /// Create a new CmdBitFlip fault
    ///
    /// # Arguments
    ///
    /// * `xor_value` - The XOR value to apply to the command.
    ///
    /// # Returns
    ///
    /// * `Arc<Self>` - Returns an `Arc` containing the `CmdBitFlip` instance.
    pub fn new(xor_value: u32) -> Arc<Self> {
        Arc::new(Self { xor_value })
    }

    /// Mask of the bits an xor value can reach on an instruction of `width` bytes.
    ///
    /// Bits above `width * 8` are dropped, because the xor value is applied byte
    /// wise over the instruction and there is no byte left for them to land in.
    fn width_mask(width: usize) -> u32 {
        match width {
            0 => 0,
            w if w >= MAX_INSTRUCTION_BYTES => u32::MAX,
            w => (1u32 << (w * 8)) - 1,
        }
    }
}

impl FaultFunctions for CmdBitFlip {
    /// Executes a command bit flip fault injection.
    ///
    /// This method modifies the command code by applying an XOR operation with the specified value.
    /// It records the original and modified instructions, as well as the fault details, for analysis.
    ///
    /// # Arguments
    ///
    /// * `cpu` - The CPU instance where the fault is injected.
    /// * `fault` - The fault record containing details of the fault.
    ///
    /// # Returns
    ///
    /// * `bool` - Always returns `true` to indicate that code repair is required after the fault injection.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        // Get current assembler instruction
        let (address, original_instruction) = cpu.asm_cmd_read();

        // Set original instructions to same as the original read instructions
        let mut modified_instruction = original_instruction;

        // The xor value is applied byte wise over the instruction, so it can only
        // reach the bytes the instruction actually has. ARM Thumb instructions are
        // either 2 or 4 bytes wide, so on a 2 byte instruction everything above
        // bit 15 never touches the instruction stream at all: `cmdbf_00010000` up
        // to `cmdbf_80000000` are silent no-ops there, while they do flip a bit on
        // a 4 byte instruction. Reducing the value to the width of the instruction
        // makes that limit explicit instead of leaving it to the loop bounds, and
        // keeps the indexing inside `to_le_bytes()` for any instruction length.
        let width = modified_instruction.len().min(MAX_INSTRUCTION_BYTES);
        let effective_xor = self.xor_value & Self::width_mask(width);

        // Manipulate the read command with the reduced xor value
        for (i, byte) in modified_instruction
            .as_mut_slice()
            .iter_mut()
            .take(width)
            .enumerate()
        {
            *byte ^= effective_xor.to_le_bytes()[i];
        }
        cpu.asm_cmd_write(address, &modified_instruction).unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!(
                "Command BitFlip (cmdbf_{:08x}) 0x{:x} -> 0x{:x}",
                self.xor_value,
                original_instruction
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (*b as u32) << (i * 8) as u32)
                    .sum::<u32>(),
                modified_instruction
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (*b as u32) << (i * 8) as u32)
                    .sum::<u32>()
            ),
            data: original_instruction.to_vec(),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instruction: original_instruction.to_vec(),
            modified_instruction: modified_instruction.to_vec(),
            record,
            fault: fault.clone(),
        });

        // Trigger code repair after fault injection
        true
    }

    /// Filtering of traces to reduce the number of traces to analyze.
    ///
    /// # Arguments
    ///
    /// * `records` - The trace records to filter.
    /// * `cs` - The disassembly context.
    fn filter(&self, _records: &mut TraceElement, _cs: &Disassembly) {}

    /// Try to parse a CmdBitFlip fault from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string.
    ///
    /// # Returns
    ///
    /// * `Option<FaultType>` - Returns the fault type if successful, otherwise `None`.
    fn parse(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute_1 = collect.get(1).copied()?;
        // check if fault type is cmd bit flip
        if fault_type == "cmdbf" {
            // check if attribute is a valid value
            if let Ok(xor_value) = u32::from_str_radix(attribute_1, 16) {
                // return CmdBitFlip struct
                return Some(Self::new(xor_value));
            }
        }
        None
    }

    /// Get the list of possible/good faults.
    ///
    /// # Returns
    ///
    /// * `Vec<String>` - Returns a vector of fault names.
    fn get_list(&self) -> Vec<String> {
        let mut list = Vec::new();
        // Generate a list of all possible cmd bitflips
        // Values will look like: cmdbf_00000001, cmdbf_00000002, ...
        //
        // All 32 bits are listed because the campaign does not know in advance which
        // instruction a fault will hit. On a 4 byte instruction every entry flips a
        // bit; on a 2 byte instruction the entries above `cmdbf_00008000` are reduced
        // away by `execute()` and leave the instruction unchanged (see `width_mask`).
        for index in 0..=31 {
            list.push(format!("cmdbf_{:08x}", 1 << index));
        }
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// The xor value can only reach the bytes the instruction actually has.
    fn width_mask_limits_value_to_instruction_width() {
        assert_eq!(0x0000_0000, CmdBitFlip::width_mask(0));
        assert_eq!(0x0000_00FF, CmdBitFlip::width_mask(1));
        assert_eq!(0x0000_FFFF, CmdBitFlip::width_mask(2));
        assert_eq!(0x00FF_FFFF, CmdBitFlip::width_mask(3));
        assert_eq!(0xFFFF_FFFF, CmdBitFlip::width_mask(4));
        // No overflow for values that can never occur as an instruction width
        assert_eq!(0xFFFF_FFFF, CmdBitFlip::width_mask(8));
    }

    #[test]
    /// On a 2 byte Thumb instruction the upper 16 bit are reduced away, so those
    /// list entries cannot change the instruction stream.
    fn upper_bits_are_a_no_op_on_two_byte_instructions() {
        let mask = CmdBitFlip::width_mask(2);
        for index in 16..=31 {
            assert_eq!(
                0,
                (1u32 << index) & mask,
                "cmdbf_{:08x} must not reach a 2 byte instruction",
                1u32 << index
            );
        }
        for index in 0..16 {
            assert_ne!(
                0,
                (1u32 << index) & mask,
                "cmdbf_{:08x} must reach a 2 byte instruction",
                1u32 << index
            );
        }
    }
}
