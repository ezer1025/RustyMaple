use crate::db::model::user;
use crate::net::handler::GenericHandler;
use bytes::{Buf, BufMut, BytesMut};
use log::warn;
use std::{env, time::SystemTime};

pub struct LoginHandler {}

impl GenericHandler for LoginHandler {
    fn handle(&self, buffer: Vec<u8>, _buffer_size: usize) -> (Vec<u8>, usize) {
        let mut bytes = &buffer.clone()[..];

        let (response, response_len) = match bytes.get_u16_le() {
            0x1bu16 => Self::login(&mut bytes),
            _ => (Vec::new(), 0),
        };
        return (response, response_len);
    }
}

impl LoginHandler {
    fn login(buffer: &mut &[u8]) -> (Vec<u8>, usize) {
        let username_length = buffer.get_u16_le();
        let mut username = vec![0u8; username_length as usize];
        buffer.copy_to_slice(&mut username);

        let password_length = buffer.get_u16_le();
        let mut password = vec![0u8; password_length as usize];
        buffer.copy_to_slice(&mut password);

        let mut response = BytesMut::new();
        response.put_u16_le(0); // OPCODE

        match std::str::from_utf8(&username[..]) {
            Ok(string_username) => match std::str::from_utf8(&password[..]) {
                Ok(string_password) => match user::get_user(string_username) {
                    Ok(some_user) => match some_user {
                        Some(user) => {
                            if user.logged_in {
                                create_simple_login_response(
                                    &mut response,
                                    LoginResponseType::AlreadyLoggedIn,
                                );
                            } else {
                                if user.ban_reset_date > SystemTime::now() {
                                    match user.ban_reset_date.duration_since(SystemTime::UNIX_EPOCH) {
                                        Ok(duraion) => {
                                            create_banned_login_response(&mut response, user.ban_reason as u8, duraion.as_secs());
                                        },
                                        Err(error) => {
                                            warn!("Unable to calculate SystemTime UTC [{}]", error);
                                            create_simple_login_response(&mut response, LoginResponseType::ServerError);
                                        }
                                    }
                                } else {
                                    match user::check_user_password(&user, string_password) {
                                        Ok(is_password_correct) => {
                                            if is_password_correct {
                                                // password is correct
                                            } else {
                                                create_simple_login_response(
                                                    &mut response,
                                                    LoginResponseType::IncorrectPassword,
                                                )
                                            }
                                        }
                                        Err(error) => {
                                            warn!("Problem querying the database [{}]", error);
                                            create_simple_login_response(
                                                &mut response,
                                                LoginResponseType::ServerError,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            match env::var("AUTO_REGISTER") {
                                Ok(auto_register) => {
                                    if auto_register.eq("true") {
                                        // create new user
                                    } else {
                                        create_simple_login_response(
                                            &mut response,
                                            LoginResponseType::NotRegistered,
                                        );
                                    }
                                }
                                Err(error) => {
                                    warn!(
                                        "Unable to read AUTO_REGISTER value from .env [{}]",
                                        error
                                    );
                                    create_simple_login_response(
                                        &mut response,
                                        LoginResponseType::NotRegistered,
                                    );
                                }
                            }
                        }
                    },
                    Err(error) => {
                        warn!("Problem querying the database [{}]", error);
                        create_simple_login_response(&mut response, LoginResponseType::ServerError);
                    }
                },
                Err(error) => {
                    warn!("Unable to convert vec[u8] to String [{}]", error);
                    create_simple_login_response(&mut response, LoginResponseType::ServerError);
                }
            },
            Err(error) => {
                warn!("Unable to convert vec[u8] to String [{}]", error);
                create_simple_login_response(&mut response, LoginResponseType::ServerError);
            }
        };

        /*
         *   2: Banned<br>
         *   3: ID deleted or blocked<br>
         *   4: Incorrect password<br>
         *   5: Not a registered id<br>
         *   6: System error<br>
         *   7: Already logged in<br>
         *   8: System error<br>
         *   9: System error<br>
         *   10: Cannot process so many connections<br>
         *   11: Only users older than 20 can use this channel
         */
        (response.to_vec(), response.len())
    }
}

fn create_simple_login_response(buffer: &mut BytesMut, return_code: LoginResponseType) {
    buffer.put_u16_le(return_code as u16);
    buffer.put_u32_le(0);
}

fn create_banned_login_response(buffer: &mut BytesMut, ban_reason: u8, ban_reset_date: u64) {
    buffer.put_u16_le(LoginResponseType::Banned as u16);
    buffer.put_u32_le(0);
    buffer.put_u8(ban_reason);
    buffer.put_u64_le(ban_reset_date);
}

enum LoginResponseType {
    Banned = 2,
    IncorrectPassword = 4,
    NotRegistered = 5,
    ServerError = 6,
    AlreadyLoggedIn = 7,
}
