use crate::db::db;
use crate::db::schema::users;
use bcrypt;
use diesel::prelude::*;
use std::error::Error;
use std::time::SystemTime;

#[derive(Queryable)]
pub struct User {
    pub username: String,
    pub is_female: bool,
    pub is_admin: bool,
    pub logged_in: bool,
    pub password: String,
    pub salt: Vec<u8>,
    pub creation_date: SystemTime,
    pub ban_reason: i16,
    pub ban_reset_date: SystemTime,
    pub mute_reason: i16,
    pub mute_reset_date: SystemTime 
}

pub fn get_user(username: &str) -> Result<Option<User>, Box<dyn Error>> {
    let mut db_connection = db::connection()?;

    match users::table.filter(users::username.eq(username)).first::<User>(&mut db_connection) {
        Ok(result) => Ok(Some(result)),
        Err(diesel::result::Error::NotFound) => Ok(None),
        Err(error) => Err(error.into())
    }
}

pub fn check_user_password(user: &User, password: &str) -> Result<bool, Box<dyn Error>> {
    Ok(bcrypt::verify(password, &user.password)?)
}