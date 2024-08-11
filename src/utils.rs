use num_bigint::BigUint;
use starknet::core::types::FieldElement;
use anyhow::anyhow;

pub fn felt_to_hex(value: &FieldElement, with_prefix: bool) -> String {
    match with_prefix {
        true => format!("0x{}", felt_to_hex(value, false)),
        false => BigUint::from_bytes_be(&value.to_bytes_be()).to_str_radix(16),
    }
}

pub fn val_or_err<T>(
    a: Result<T, anyhow::Error>,
    b: Result<T, anyhow::Error>,
) -> Result<T, anyhow::Error>
where
    T: PartialEq + std::fmt::Display,
{
    match (a, b) {
        (Ok(val_a), Ok(val_b)) => match val_a == val_b {
            true => Ok(val_a),
            false => Err(anyhow!("Values were not the same")
                .context(format!("Left value: {}", val_a))
                .context(format!("Right value: {}", val_b))),
        },
        (Ok(val_a), Err(_)) => Ok(val_a),
        (Err(_), Ok(val_b)) => Ok(val_b),
        (Err(err_a), Err(err_b)) => Err(anyhow!("No value").context(err_a).context(err_b)),
    }
}
