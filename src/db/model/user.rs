use crate::db::{db, schema};
use crate::db::schema::users::{self, pin_code, id};
use bcrypt;
use diesel::prelude::*;
use std::error::Error;
use std::time::SystemTime;

#[derive(Queryable, Identifiable, AsChangeset)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub is_female: bool,
    pub is_admin: bool,
    pub logged_in: bool,
    pub password: String,
    pub salt: Vec<u8>,
    pub pin_code: Option<String>,
    pub creation_date: SystemTime,
    pub ban_reason: i16,
    pub ban_reset_date: SystemTime,
    pub mute_reason: i16,
    pub mute_reset_date: SystemTime,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub is_female: bool,
    pub is_admin: bool,
    pub logged_in: bool,
    pub password: String,
    pub salt: Vec<u8>,
    pub pin_code: Option<String>,
    pub creation_date: SystemTime,
    pub ban_reason: i16,
    pub ban_reset_date: SystemTime,
    pub mute_reason: i16,
    pub mute_reset_date: SystemTime,
}

impl User {
    pub fn get_by_username(username: &str) -> Result<Option<User>, Box<dyn Error>> {
        let mut db_connection = db::DBPool::get()?.connection()?;

        match users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut db_connection)
        {
            Ok(result) => Ok(Some(result)),
            Err(diesel::result::Error::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn create(new_user: NewUser) -> Result<User, Box<dyn Error>> {
        let mut db_connection = db::DBPool::get()?.connection()?;

        match diesel::insert_into(users::dsl::users)
            .values(&new_user)
            .get_result::<User>(&mut db_connection)
        {
            Ok(user) => Ok(user),
            Err(error) => Err(error.into()),
        }
    }

    pub fn verify_password(&self, password: &str) -> bcrypt::BcryptResult<bool> {
        bcrypt::verify(password, &self.password)
    }

    pub fn update_pin_code(&mut self, new_pin_code: String) -> Result<usize, Box<dyn Error>> {
        let mut db_connection = db::DBPool::get()?.connection()?;
        match diesel::update(schema::users::dsl::users).filter(id.eq(self.id)).set(pin_code.eq(Some(&new_pin_code))).execute(&mut db_connection) {
            Ok(affected_rows) => {
                self.pin_code = Some(new_pin_code);
                Ok(affected_rows)
            },
            Err(error) => Err(error.into())
        }
    }
}