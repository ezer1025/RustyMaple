use crate::defaults;

use aes::Aes256;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Ecb};
use bytes::{BufMut, BytesMut};
use std::cmp::min;
use std::error;

const SEQUENCE_SHIFTING_KEY: [u8; 256] = [
    0xEC, 0x3F, 0x77, 0xA4, 0x45, 0xD0, 0x71, 0xBF, 0xB7, 0x98, 0x20, 0xFC, 0x4B, 0xE9, 0xB3, 0xE1,
    0x5C, 0x22, 0xF7, 0x0C, 0x44, 0x1B, 0x81, 0xBD, 0x63, 0x8D, 0xD4, 0xC3, 0xF2, 0x10, 0x19, 0xE0,
    0xFB, 0xA1, 0x6E, 0x66, 0xEA, 0xAE, 0xD6, 0xCE, 0x06, 0x18, 0x4E, 0xEB, 0x78, 0x95, 0xDB, 0xBA,
    0xB6, 0x42, 0x7A, 0x2A, 0x83, 0x0B, 0x54, 0x67, 0x6D, 0xE8, 0x65, 0xE7, 0x2F, 0x07, 0xF3, 0xAA,
    0x27, 0x7B, 0x85, 0xB0, 0x26, 0xFD, 0x8B, 0xA9, 0xFA, 0xBE, 0xA8, 0xD7, 0xCB, 0xCC, 0x92, 0xDA,
    0xF9, 0x93, 0x60, 0x2D, 0xDD, 0xD2, 0xA2, 0x9B, 0x39, 0x5F, 0x82, 0x21, 0x4C, 0x69, 0xF8, 0x31,
    0x87, 0xEE, 0x8E, 0xAD, 0x8C, 0x6A, 0xBC, 0xB5, 0x6B, 0x59, 0x13, 0xF1, 0x04, 0x00, 0xF6, 0x5A,
    0x35, 0x79, 0x48, 0x8F, 0x15, 0xCD, 0x97, 0x57, 0x12, 0x3E, 0x37, 0xFF, 0x9D, 0x4F, 0x51, 0xF5,
    0xA3, 0x70, 0xBB, 0x14, 0x75, 0xC2, 0xB8, 0x72, 0xC0, 0xED, 0x7D, 0x68, 0xC9, 0x2E, 0x0D, 0x62,
    0x46, 0x17, 0x11, 0x4D, 0x6C, 0xC4, 0x7E, 0x53, 0xC1, 0x25, 0xC7, 0x9A, 0x1C, 0x88, 0x58, 0x2C,
    0x89, 0xDC, 0x02, 0x64, 0x40, 0x01, 0x5D, 0x38, 0xA5, 0xE2, 0xAF, 0x55, 0xD5, 0xEF, 0x1A, 0x7C,
    0xA7, 0x5B, 0xA6, 0x6F, 0x86, 0x9F, 0x73, 0xE6, 0x0A, 0xDE, 0x2B, 0x99, 0x4A, 0x47, 0x9C, 0xDF,
    0x09, 0x76, 0x9E, 0x30, 0x0E, 0xE4, 0xB2, 0x94, 0xA0, 0x3B, 0x34, 0x1D, 0x28, 0x0F, 0x36, 0xE3,
    0x23, 0xB4, 0x03, 0xD8, 0x90, 0xC8, 0x3C, 0xFE, 0x5E, 0x32, 0x24, 0x50, 0x1F, 0x3A, 0x43, 0x8A,
    0x96, 0x41, 0x74, 0xAC, 0x52, 0x33, 0xF0, 0xD9, 0x29, 0x80, 0xB1, 0x16, 0xD3, 0xAB, 0x91, 0xB9,
    0x84, 0x7F, 0x61, 0x1E, 0xCF, 0xC5, 0xD1, 0x56, 0x3D, 0xCA, 0xF4, 0x05, 0xC6, 0xE5, 0x08, 0x49,
];

const AES_KEY: [u8; defaults::AES_KEY_SIZE] = [
    0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xB4, 0x00, 0x00, 0x00,
    0x1B, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00,
];

fn maple_custom_encrypt_internal(buffer: &Vec<u8>) -> Vec<u8> {
    let mut rememberer: u8;
    let mut current_byte: u8;
    let mut length: u8;
    let mut result = buffer.clone();

    for loop_index in 0..6 {
        rememberer = 0;
        length = result.len() as u8;

        if loop_index % 2 == 0 {
            for indexer in 0..result.len() {
                current_byte = result[indexer as usize];
                current_byte = current_byte.rotate_left(3);
                current_byte = current_byte.wrapping_add(length); // current_byte += length;
                current_byte ^= rememberer;
                rememberer = current_byte;
                current_byte = current_byte.rotate_right(length as u32);
                current_byte = (!current_byte) & 0xFF;
                current_byte = current_byte.wrapping_add(0x48); // current_byte += 0x48;
                length = length.wrapping_sub(1); // length -= 1;
                result[indexer as usize] = current_byte;
            }
        } else {
            for indexer in (result.len() - 1..=0).rev() {
                current_byte = result[indexer as usize];
                current_byte = current_byte.rotate_left(4);
                current_byte = current_byte.wrapping_add(length); // current_byte += length;
                current_byte ^= rememberer;
                rememberer = current_byte;
                current_byte ^= 0x13;
                current_byte = current_byte.rotate_right(3);
                length = length.wrapping_sub(1); // length -= 1;
                result[indexer as usize] = current_byte;
            }
        }
    }

    result
}

fn maple_custom_decrypt_internals(buffer: &Vec<u8>) -> Vec<u8> {
    let mut length: u8;
    let mut rememberer: u8;
    let mut current_byte: u8;
    let mut next_rememberer: u8;
    let mut result = buffer.clone();

    for loop_index in 1..=6 {
        rememberer = 0;
        length = result.len() as u8;

        if loop_index % 2 == 0 {
            for indexer in 0..result.len() {
                current_byte = result[indexer as usize];
                current_byte = current_byte.wrapping_sub(0x48); // current_byte -= 0x48;
                current_byte = (!current_byte) & 0xFF;
                current_byte = current_byte.rotate_left(length as u32);
                next_rememberer = current_byte;
                current_byte ^= rememberer;
                rememberer = next_rememberer;
                current_byte = current_byte.wrapping_sub(length); // current_byte -= length;
                current_byte = current_byte.rotate_right(3);
                result[indexer as usize] = current_byte;
                length = length.wrapping_sub(1); // length -= 1;
            }
        } else {
            for indexer in (result.len() - 1..=0).rev() {
                current_byte = result[indexer as usize];
                current_byte = current_byte.rotate_left(3);
                current_byte ^= 0x13;
                next_rememberer = current_byte;
                current_byte ^= rememberer;
                rememberer = next_rememberer;
                current_byte = current_byte.wrapping_sub(length); // current_byte -= length;
                current_byte = current_byte.rotate_right(4);
                result[indexer as usize] = current_byte;
                length = length.wrapping_sub(1); // length -= 1;
            }
        }
    }

    result
}

fn morph_sequence(
    current_sequence: &[u8; defaults::USER_SEQUENCE_SIZE],
) -> [u8; defaults::USER_SEQUENCE_SIZE] {
    let mut current_byte: u8;
    let mut current_table_byte: u8;
    let mut new_sequence: [u8; defaults::USER_SEQUENCE_SIZE] = [0xF2, 0x53, 0x50, 0xC6];

    for indexer in 0..defaults::USER_SEQUENCE_SIZE {
        current_byte = current_sequence[indexer];
        current_table_byte = SEQUENCE_SHIFTING_KEY[current_byte as usize];

        new_sequence[0] = new_sequence[0].wrapping_add(
            SEQUENCE_SHIFTING_KEY[new_sequence[1] as usize].wrapping_sub(current_byte),
        ); // new_sequence[0] += SEQUENCE_SHIFTING_KEY[new_sequence[1] as usize] - current_byte;
        new_sequence[1] = new_sequence[1].wrapping_sub(new_sequence[2] ^ current_table_byte); // new_sequence[1] -= new_sequence[2] ^ current_table_byte;
        new_sequence[2] ^=
            SEQUENCE_SHIFTING_KEY[new_sequence[3] as usize].wrapping_add(current_byte); // new_sequence[2] ^= SEQUENCE_SHIFTING_KEY[new_sequence[3] as usize] + current_byte;
        new_sequence[3] =
            new_sequence[3].wrapping_sub(new_sequence[0].wrapping_sub(current_table_byte)); // new_sequence[3] -= new_sequence[0] - current_table_byte;

        let mut val: usize = (new_sequence[0] as usize
            | (((new_sequence[1] & 0xFF) as usize) << 8)
            | (((new_sequence[2] & 0xFF) as usize) << 16)
            | (((new_sequence[3] & 0xFF) as usize) << 24))
            >> 0;

        let mut val2: usize = val >> 0x1D;

        val = (val << 0x03) >> 0;
        val2 |= val;

        new_sequence[0] = val2 as u8;
        new_sequence[1] = (val2 >> 8) as u8;
        new_sequence[2] = (val2 >> 16) as u8;
        new_sequence[3] = (val2 >> 24) as u8;
    }

    new_sequence
}

fn maple_custom_aes_crypt(
    buffer: Vec<u8>,
    user_sequence: &[u8; defaults::USER_SEQUENCE_SIZE],
    encrypt: bool,
) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut block_size: usize;
    let mut data_crypted = 0;
    let mut user_sequence_block: Vec<u8> = Vec::with_capacity(defaults::AES_BLOCK_SIZE);
    let mut result = buffer.clone();

    for _ in (0..defaults::AES_BLOCK_SIZE).step_by(defaults::USER_SEQUENCE_SIZE) {
        for sequence_indexer in 0..defaults::USER_SEQUENCE_SIZE {
            user_sequence_block.push(user_sequence[sequence_indexer]);
        }
    }

    while data_crypted < result.len() {
        let mut xor_key = user_sequence_block.clone();

        block_size = min(
            result.len() - data_crypted,
            match data_crypted {
                0 => 1456,
                _ => 1460,
            },
        );

        for byte_in_block in 0..block_size {
            if byte_in_block % defaults::AES_BLOCK_SIZE == 0 {
                xor_key = match encrypt {
                    true => match aes_encrypt(&xor_key) {
                        Ok(encrypted_block) => encrypted_block,
                        Err(error) => return Err(error.into()),
                    },
                    false => match aes_decrypt(&xor_key) {
                        Ok(decrypted_block) => decrypted_block,
                        Err(error) => return Err(error.into()),
                    },
                }
            }

            result[data_crypted + byte_in_block] ^=
                xor_key[byte_in_block % defaults::AES_BLOCK_SIZE];
        }

        data_crypted += block_size;
    }

    Ok(result)
}

fn aes_encrypt(buffer: &[u8]) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let cipher: Ecb<Aes256, NoPadding> = match Ecb::new_var(&AES_KEY, Default::default()) {
        Ok(cipher) => cipher,
        Err(error) => return Err(error.into()),
    };

    Ok(cipher.encrypt_vec(buffer))
}

fn aes_decrypt(buffer: &[u8]) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let cipher: Ecb<Aes256, NoPadding> = match Ecb::new_var(&AES_KEY, Default::default()) {
        Ok(cipher) => cipher,
        Err(error) => return Err(error.into()),
    };
    match cipher.decrypt_vec(buffer) {
        Ok(decrypted_text) => Ok(decrypted_text),
        Err(error) => Err(error.into()),
    }
}

///
/// PUBLIC FUNCTIONS
///

pub fn maple_custom_encrypt(
    buffer: &Vec<u8>,
    user_sequence: &mut [u8; defaults::USER_SEQUENCE_SIZE],
) -> Result<Vec<u8>, Box<dyn error::Error>> {
    match maple_custom_aes_crypt(maple_custom_encrypt_internal(buffer), user_sequence, true) {
        Ok(encrypted_block) => {
            *user_sequence = morph_sequence(user_sequence);
            Ok(encrypted_block)
        }
        Err(error) => Err(error.into()),
    }
}

pub fn maple_custom_decrypt(
    buffer: &Vec<u8>,
    user_sequence: &mut [u8; defaults::USER_SEQUENCE_SIZE],
) -> Result<Vec<u8>, Box<dyn error::Error>> {
    match maple_custom_aes_crypt(maple_custom_decrypt_internals(buffer), user_sequence, false) {
        Ok(decrypted_block) => {
            *user_sequence = morph_sequence(user_sequence);
            Ok(decrypted_block)
        }
        Err(error) => Err(error.into()),
    }
}

pub fn get_packet_length(header: &Vec<u8>) -> usize {
    let length = (header[0] as usize)
        | (header[1] as usize) << 8
        | (header[2] as usize) << 16
        | (header[3] as usize) << 24;
    (length >> 16) ^ (length & 0xFFFF) & 0xFFFF
}

pub fn generate_packet_header(
    length: u16,
    user_sequence: &[u8; defaults::USER_SEQUENCE_SIZE],
    version: &u16,
) -> Vec<u8> {
    let mut result = BytesMut::with_capacity(defaults::DEFAULT_HEADER_LENGTH);

    let first_word: u16 =
        (user_sequence[2] as u16 | ((user_sequence[3] as u32) << 8) as u16) ^ version;
    let second_word: u16 = first_word ^ length;

    result.put_u16_le(first_word);
    result.put_u16_le(second_word);

    result.to_vec()
}
