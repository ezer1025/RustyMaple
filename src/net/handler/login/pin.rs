use std::sync::{Arc, Mutex};
use crate::net::client::Client;
use bytes::{Buf, BufMut, BytesMut};
use log::{warn, error};

pub fn insert_pin_code(client: Arc<Mutex<Client>>, buffer: &mut &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut response = BytesMut::new();
    let choice = buffer.get_u8();

    let mut client_guard = match client.lock() {
        Ok(guard) => guard,
        Err(error) => {
            warn!("Unable to lock Client Mutext [{}]", error);
            return None;
        }
    };

    if choice == 0 {
        client_guard.user = None;
        return None;
    } else {
        if !buffer.is_empty() {
            let pin_code_length = buffer.get_u16_le();
            let mut new_pin_code = vec![0u8; pin_code_length as usize];
            buffer.copy_to_slice(&mut new_pin_code);

            match String::from_utf8(new_pin_code) {
                Ok(string_pin_code) => {
                    match &client_guard.user {
                        Some(user_mutex) => {
                            let mut user = match user_mutex.lock() {
                                Ok(user) => user,
                                Err(error) => {
                                    warn!("Unable to lock User Mutext [{}]", error);
                                    return None;
                                }
                            };

                            match user.update_pin_code(string_pin_code) {
                                Ok(_) => create_simple_pin_response(&mut response, PinResponseType::PinAccepted),
                                Err(error) => {
                                    warn!("Unable to update User pin code [{}]", error);
                                    return None;
                                }
                            };
                        }
                        None => {
                            error!("Received authenticated packet from non-authenticated user");
                            return None;
                        }
                    };
                }
                Err(error) => {
                    warn!("Unable to convert byte array to String [{}]", error);
                    return None;
                }
            };
        } else {
            return None;
        }
    }

    Some((response.to_vec(), response.len()))
}

pub fn check_pin_code(client: Arc<Mutex<Client>>, buffer: &mut &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut response = BytesMut::new();
    let sub_stage = buffer.get_u8();
    let mut client_guard = match client.lock() {
        Ok(guard) => guard,
        Err(error) => {
            warn!("Unable to lock Client Mutext [{}]", error);
            return None;
        }
    };

    if buffer.is_empty() {
        if sub_stage == 0 {
            client_guard.user = None;
        }

        return None;
    } else {
        let stage = buffer.get_u8();

        if stage == 1 {
            if sub_stage == 1 {
                match &client_guard.user {
                    Some(user_mutex) => match user_mutex.lock() {
                        Ok(user) => match user.pin_code {
                            Some(_) => create_simple_pin_response(
                                &mut response,
                                PinResponseType::EnterPin,
                            ),
                            None => create_simple_pin_response(
                                &mut response,
                                PinResponseType::InsertNewPin,
                            ),
                        },
                        Err(error) => {
                            warn!("Unable to lock User Mutex [{}]", error);
                            return None;
                        }
                    },
                    None => {
                        error!("Received authenticated packet from non-authenticated user");
                        return None;
                    }
                };
            }
        } else if stage == 0 {
            buffer.get_u32();
            let pin_code_length = buffer.get_u16_le();
            let mut pin_code = vec![0u8; pin_code_length as usize];
            buffer.copy_to_slice(&mut pin_code);

            let str_pin_code = match String::from_utf8(pin_code) {
                Ok(str) => str,
                Err(error) => {
                    warn!("Unable to convert bytes string to String [{}]", error);
                    return None;
                }
            };

            match &client_guard.user {
                Some(user_mutex) => match user_mutex.lock() {
                    Ok(user) => match &user.pin_code {
                        Some(db_pin_code) => {
                            if db_pin_code.eq(&str_pin_code) {
                                if sub_stage == 1 {
                                    create_simple_pin_response(
                                        &mut response,
                                        PinResponseType::PinAccepted,
                                    );
                                } else if sub_stage == 2 {
                                    create_simple_pin_response(
                                        &mut response,
                                        PinResponseType::InsertNewPin,
                                    );
                                } else {
                                    return None;
                                }
                            } else {
                                create_simple_pin_response(
                                    &mut response,
                                    PinResponseType::PinFailed,
                                );
                            }
                        },
                        None => create_simple_pin_response(&mut response, PinResponseType::InsertNewPin)
                    },
                    Err(error) => {
                        warn!("Unable to lock User Mutext [{}]", error);
                        return None;
                    }
                },
                None => {
                    error!("Received authenticated packet from non-authenticated user");
                    return None;
                }
            };
        }
    }

    Some((response.to_vec(), response.len()))
}

fn create_simple_pin_response(buffer: &mut BytesMut, response_code: PinResponseType) {
    buffer.put_u16_le(0x0D); // OPCODE
    buffer.put_u8(response_code as u8);
}

enum PinResponseType {
    PinAccepted = 0,
    InsertNewPin = 1,
    PinFailed = 2,
    SystemError = 3,
    EnterPin = 4,
    AlreadyLoggedIn = 7,
}
