use diesel::pg::PgConnection;
use diesel::r2d2::ConnectionManager;
use lazy_static::lazy_static;
use r2d2;
use std::env;
use log::error;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

lazy_static! {
    static ref POOL: Pool = {
        let db_url = match env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                error!("Database url not set");
                std::process::exit(1);
            }
        };

        let manager = ConnectionManager::<PgConnection>::new(db_url);
        
        match Pool::new(manager) {
            Ok(pool_manager) => pool_manager,
            Err(error) => {
                error!("Unable to create db pool [{}]", error);
                std::process::exit(1);
            }
        }
    };
}

pub fn connection() -> Result<DbConnection, r2d2::Error> {
    POOL.get()
}

pub fn init() {
    lazy_static::initialize(&POOL);
}