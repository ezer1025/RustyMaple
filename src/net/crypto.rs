use crate::defaults;

pub fn get_packet_length(header: &Vec<u8>) -> usize {
    let length = (header[0] as usize)
        | (header[1] as usize) << 8
        | (header[2] as usize) << 16
        | (header[3] as usize) << 24;
    (length >> 16) ^ (length & 0xFFFF) & 0xFFFF
}

fn maple_custom_crypt_encrypt(buffer: &mut Vec<u8>) -> &mut Vec<u8> {
    let mut rememberer: u8;
    let mut current_byte: u8;
    let mut length: u8;

    for loop_index in 0..6 {
        rememberer = 0;
        length = buffer.len() as u8 & 0xFF;

        if loop_index % 2 == 0 {
            for indexer in 0..buffer.len() {
                current_byte = buffer[indexer as usize];
                current_byte = current_byte.rotate_left(3);
                current_byte += length;
                current_byte ^= rememberer;
                rememberer = current_byte;
                current_byte = current_byte.rotate_right((length as u32) & 0xFF);
                current_byte = !current_byte & 0xFF;
                current_byte += 0x48;
                length -= 1;
                buffer[indexer as usize] = current_byte;
            }
        } else {
            for indexer in (buffer.len() - 1..=0).rev() {
                current_byte = buffer[indexer as usize];
                current_byte = current_byte.rotate_left(4);
                current_byte += length;
                current_byte ^= rememberer;
                rememberer = current_byte;
                current_byte ^= 0x13;
                current_byte = current_byte.rotate_right(3);
                length -= 1;
                buffer[indexer as usize] = current_byte;
            }
        }
    }
    buffer
}

fn maple_custom_crypt_decrypt(buffer: &mut Vec<u8>) -> &mut Vec<u8> {
    let mut current_byte: u8;
    let mut rememberer: u8;
    let mut next_rememberer: u8;
    let mut length: u8;

    for loop_index in 1..=6 {
        rememberer = 0;
        length = buffer.len() as u8 & 0xFF;

        if loop_index % 2 == 0 {
            for indexer in 0..length {
                current_byte = buffer[indexer as usize];
                current_byte -= 0x48;
                current_byte = !current_byte & 0xFF;
                current_byte = current_byte.rotate_left((length as u32) & 0xFF);
                next_rememberer = current_byte;
                current_byte ^= rememberer;
                rememberer = next_rememberer;
                current_byte -= length;
                current_byte = current_byte.rotate_right(3);
                buffer[indexer as usize] = current_byte;
                length -= 1;
            }
        } else {
            for indexer in (buffer.len() - 1..=0).rev() {
                current_byte = buffer[indexer as usize];
                current_byte = current_byte.rotate_left(3);
                current_byte ^= 0x13;
                next_rememberer = current_byte;
                current_byte ^= rememberer;
                rememberer = next_rememberer;
                current_byte -= length;
                current_byte = current_byte.rotate_right(4);
                buffer[indexer as usize] = current_byte;
                length -= 1;
            }
        }
    }
    buffer
}
