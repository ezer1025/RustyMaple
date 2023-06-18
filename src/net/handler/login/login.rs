use crate::db::model::user::{self, User};
use crate::net::client::Client;
use bytes::{Buf, BufMut, BytesMut};
use log::warn;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::error::Error;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::{env, time::SystemTime};

pub fn login(client: Arc<Mutex<Client>>, buffer: &mut &[u8]) -> Option<(Vec<u8>, usize)> {
    let username_length = buffer.get_u16_le();
    let mut username = vec![0u8; username_length as usize];
    buffer.copy_to_slice(&mut username);

    let password_length = buffer.get_u16_le();
    let mut password = vec![0u8; password_length as usize];
    buffer.copy_to_slice(&mut password);

    let mut response = BytesMut::new();

    match std::str::from_utf8(&username[..]) {
        Ok(string_username) => match std::str::from_utf8(&password[..]) {
            Ok(string_password) => match user::User::get_by_username(string_username) {
                Ok(some_user) => match some_user {
                    Some(user) => {
                        match user.verify_password(string_password) {
                            Ok(is_password_correct) => {
                                if is_password_correct {
                                    if user.logged_in {
                                        create_simple_login_response(
                                            &mut response,
                                            LoginResponseType::AlreadyLoggedIn,
                                        );
                                    } else {
                                        if user.ban_reset_date > SystemTime::now() {
                                            match user
                                                .ban_reset_date
                                                .duration_since(SystemTime::UNIX_EPOCH)
                                            {
                                                Ok(duraion) => {
                                                    create_banned_login_response(
                                                        &mut response,
                                                        user.ban_reason as u8,
                                                        duraion.as_secs(),
                                                    );
                                                }
                                                Err(error) => {
                                                    warn!("Unable to calculate SystemTime UTC [{}]", error);
                                                    create_simple_login_response(
                                                        &mut response,
                                                        LoginResponseType::ServerError,
                                                    );
                                                }
                                            }
                                        } else {
                                            match create_login_success_response(
                                                &mut response,
                                                &user,
                                            ) {
                                                Ok(()) => {
                                                    match client.lock() {
                                                        Ok(ref mut client_guard) => {
                                                            client_guard.user =
                                                                Some(Mutex::new(user))
                                                        }
                                                        Err(error) => {
                                                            warn!("Unable to lock Client Mutext [{}]", error);
                                                            response.clear();
                                                            create_simple_login_response(
                                                                &mut response,
                                                                LoginResponseType::ServerError,
                                                            );
                                                        }
                                                    };
                                                }
                                                Err(error) => {
                                                    warn!("Unable to create login success packet [{}]", error);
                                                    response.clear();
                                                    create_simple_login_response(
                                                        &mut response,
                                                        LoginResponseType::ServerError,
                                                    );
                                                }
                                            }
                                        }
                                    }
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
                    None => match env::var("auto_register") {
                        Ok(auto_register) => {
                            if auto_register.eq("true") {
                                let mut prng: StdRng = StdRng::from_entropy();
                                let mut salt: [u8; 16] = Default::default();

                                prng.fill(&mut salt);

                                match bcrypt::hash_with_salt(
                                    string_password,
                                    bcrypt::DEFAULT_COST,
                                    salt,
                                ) {
                                    Ok(hash_obj) => {
                                        match user::User::create(user::NewUser {
                                            username: string_username.to_string(),
                                            is_female: false,
                                            is_admin: false,
                                            logged_in: false,
                                            pin_code: None,
                                            creation_date: SystemTime::now(),
                                            ban_reason: 0,
                                            ban_reset_date: SystemTime::now(),
                                            mute_reason: 0,
                                            mute_reset_date: SystemTime::now(),
                                            password: hash_obj.to_string(),
                                            salt: hash_obj.get_salt().into(),
                                        }) {
                                            Ok(user) => {
                                                match create_login_success_response(
                                                    &mut response,
                                                    &user,
                                                ) {
                                                    Ok(()) => {
                                                        match client.lock() {
                                                            Ok(ref mut client_guard) => {
                                                                client_guard.user =
                                                                    Some(Mutex::new(user));
                                                            }
                                                            Err(error) => {
                                                                warn!("Unable to lock Client Mutext [{}]", error);
                                                                response.clear();
                                                                create_simple_login_response(
                                                                    &mut response,
                                                                    LoginResponseType::ServerError,
                                                                );
                                                            }
                                                        };
                                                    }
                                                    Err(error) => {
                                                        warn!("Unable to create login success packet [{}]", error);
                                                        response.clear();
                                                        create_simple_login_response(
                                                            &mut response,
                                                            LoginResponseType::ServerError,
                                                        );
                                                    }
                                                }
                                            }
                                            Err(error) => {
                                                warn!(
                                                    "Unable to insert new row to database [{}]",
                                                    error
                                                );
                                                create_simple_login_response(
                                                    &mut response,
                                                    LoginResponseType::NotRegistered,
                                                );
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        warn!("Unable to hash user's password [{}]", error);
                                        create_simple_login_response(
                                            &mut response,
                                            LoginResponseType::NotRegistered,
                                        );
                                    }
                                };
                            } else {
                                create_simple_login_response(
                                    &mut response,
                                    LoginResponseType::NotRegistered,
                                );
                            }
                        }
                        Err(error) => {
                            warn!("Unable to read AUTO_REGISTER value from .env [{}]", error);
                            create_simple_login_response(
                                &mut response,
                                LoginResponseType::NotRegistered,
                            );
                        }
                    },
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
    Some((response.to_vec(), response.len()))
}

fn create_simple_login_response(buffer: &mut BytesMut, return_code: LoginResponseType) {
    buffer.put_u16_le(0); // OPCODE
    buffer.put_u32_le(return_code as u32);
    buffer.put_u16_le(0);
}

fn create_banned_login_response(buffer: &mut BytesMut, ban_reason: u8, ban_reset_date: u64) {
    buffer.put_u16_le(0); // OPCODE
    buffer.put_u32_le(LoginResponseType::Banned as u32);
    buffer.put_u16_le(0);
    buffer.put_u8(ban_reason);
    buffer.put_u64_le(ban_reset_date);
}

fn create_login_success_response(buffer: &mut BytesMut, user: &User) -> Result<(), Box<dyn Error>> {
    buffer.put_u16_le(0); // OPCODE
    buffer.put_u32_le(LoginResponseType::LoginSuccess as u32);
    buffer.put_u16_le(0);

    buffer.put_u32_le(user.id as u32);
    buffer.put_u8(0);

    buffer.put_u16_le(match user.is_admin {
        true => 0x8001,
        false => 0,
    });

    buffer.put_u16_le(user.username.len() as u16);
    buffer.write_str(&user.username)?;

    buffer.put_u8(0);

    buffer.put_u8(user.mute_reason as u8);
    buffer.put_u64_le(
        user.mute_reset_date
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs(),
    );

    buffer.put_u64_le(
        user.creation_date
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs(),
    );

    buffer.put_u32_le(0);
    Ok(())
}

enum LoginResponseType {
    LoginSuccess = 0,
    Banned = 2,
    IncorrectPassword = 4,
    NotRegistered = 5,
    ServerError = 6,
    AlreadyLoggedIn = 7,
}