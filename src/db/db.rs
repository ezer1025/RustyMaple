use diesel::pg::PgConnection;
use diesel::r2d2::ConnectionManager;
use once_cell;
use once_cell::sync::OnceCell;
use r2d2;
use std::error::Error;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

pub struct DBPool {
    pool: Pool,
}

static POOL_INSTANCE: OnceCell<DBPool> = OnceCell::new();

impl DBPool {
    pub fn get() -> Result<&'static DBPool, Box<dyn Error>> {
        match POOL_INSTANCE.get() {
            Some(p) => Ok(p),
            None => Err("Database pool not initialized".into()),
        }
    }

    pub fn init(connection_url: &str) -> Result<(), Box<dyn Error>> {
        let manager = ConnectionManager::<PgConnection>::new(connection_url);

        match Pool::builder().build(manager) {
            Ok(pool_manager) => match POOL_INSTANCE.set(DBPool { pool: pool_manager }) {
                Ok(_) => Ok(()),
                Err(_) => Err("Database pool already initialized".into())
            },
            Err(error) => Err(error.into())
        }
    }

    pub fn connection(&self) -> Result<DbConnection, r2d2::Error> {
        self.pool.get()
    }
}