use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use crate::app::errors;

mod ent;

pub(crate) const DBNAME: &str = "authenticator.db";

pub struct Repo {
    db: DatabaseConnection,
    readonly: bool,
    dbpath: String,
}

impl Repo {
    pub async fn new(dbpath: String, readonly: bool) -> Result<Self, errors::Error> {
        let conn = Database::connect(Self::dsn(&dbpath, readonly))
            .await
            .map_err(|e| errors::Error::CannotOpenDatabase(dbpath.clone(), e.to_string()))?;

        Ok(Repo {
            dbpath,
            readonly,
            db: conn,
        })
    }

    fn dsn(dbpath: &String, readonly: bool) -> String {
        let mode = if readonly { "ro" } else { "rwc" };
        format!("sqlite:{}?mode={}", dbpath, mode)
    }

    pub async fn migrate(&self) -> Result<(), errors::Error> {
        migration::Migrator::up(&self.db, None)
            .await
            .map_err(|e| errors::Error::MigrateDatabase(e.to_string()))
    }
}