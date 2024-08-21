use num_bigint::BigUint;
use starknet::core::types::FieldElement;

pub fn felt_to_hex(value: &FieldElement, with_prefix: bool) -> String {
    if with_prefix {
        format!("0x{}", felt_to_hex(value, false))
    } else {
        BigUint::from_bytes_be(&value.to_bytes_be()).to_str_radix(16)
    }
}
