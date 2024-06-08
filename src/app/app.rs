use std::sync::Once;
use std::path::Path;

use crate::app::{errors, repo};
use crate::app::repo::Repo;

pub struct App {
    _cfg: AppConfig,

    repo: Option<Repo>,
}

pub struct AppConfig {
    pub db_path: String,
}

impl AppConfig {
    fn new(data_path: String) -> Self {
        AppConfig {
            db_path: Path::new(data_path.as_str()).join(repo::DBNAME).
                to_str().unwrap_or("").to_string(),
        }
    }
}

static mut APP: Option<App> = None;
static ONCE: Once = Once::new();

impl App {
    fn from(app_config: AppConfig) -> Self {
        App {
            _cfg: app_config,
            repo: None,
        }
    }

    pub async fn init(data_path: String) -> Result<(), errors::Error> {
        unsafe {
            ONCE.call_once(|| {
                APP = Some(App::from(AppConfig::new(data_path)));
            });
        }

        let app: &mut App = Self::instance();

        app.repo = Some(Repo::new(app._cfg.db_path.clone(), false).await?);

        let repo = app.repo.as_ref().unwrap();
        repo.migrate().await?;

        Ok(())
    }

    pub fn instance() -> &'static mut App {
        unsafe { APP.as_mut().unwrap() }
    }

    pub fn appinfo(&self) -> String {
        self._cfg.db_path.clone()
    }
}
