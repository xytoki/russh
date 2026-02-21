use std::str;

use crate::Error;

fn read_ssh_string<'a>(blob: &'a [u8], offset: &mut usize) -> Result<&'a [u8], Error> {
    let len_end = offset.checked_add(4).ok_or(Error::KexInit)?;
    let len_bytes = blob.get(*offset..len_end).ok_or(Error::KexInit)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    *offset = len_end;

    let end = offset.checked_add(len).ok_or(Error::KexInit)?;
    let data = blob.get(*offset..end).ok_or(Error::KexInit)?;
    *offset = end;
    Ok(data)
}

fn ensure_supported_algorithm(algo: &str) -> Result<(), Error> {
    match algo {
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" | "ecdsa-sha2-nistp256" => Ok(()),
        _ => Err(Error::WrongServerSig),
    }
}

/// Parse the algorithm name from an SSH public key blob.
///
/// SSH key blob format: string algorithm_name, ...rest
pub fn parse_key_algo(blob: &[u8]) -> Result<&str, Error> {
    let mut offset = 0;
    let algo = str::from_utf8(read_ssh_string(blob, &mut offset)?)?;
    ensure_supported_algorithm(algo)?;
    Ok(algo)
}

/// Parse an SSH signature blob.
///
/// Format: string algorithm_name, string signature_data
pub fn parse_signature(blob: &[u8]) -> Result<(&str, &[u8]), Error> {
    let mut offset = 0;
    let algo = str::from_utf8(read_ssh_string(blob, &mut offset)?)?;
    ensure_supported_algorithm(algo)?;
    let signature = read_ssh_string(blob, &mut offset)?;
    if offset != blob.len() {
        return Err(Error::WrongServerSig);
    }
    Ok((algo, signature))
}
