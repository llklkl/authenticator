use std::sync::Once;
use std::path::Path;

use crate::app::repo;

pub struct App {
    _cfg: AppConfig,
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
            _cfg: app_config
        }
    }

    pub fn init(data_path: String) {
        unsafe {
            ONCE.call_once(|| {
                APP = Some(App::from(AppConfig::new(data_path)));
            });
        }
    }

    pub fn instance() -> &'static App {
        unsafe { APP.as_ref().unwrap() }
    }

    pub fn appinfo(&self) -> String {
        self._cfg.db_path.clone()
    }
}
