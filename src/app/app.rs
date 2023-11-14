use std::sync::Once;

pub struct App {
    _cfg: AppConfig,
}

#[derive(Clone)]
pub struct AppConfig {
    pub db_path: String,
}

static mut APP: Option<App> = None;
static ONCE: Once = Once::new();

impl App {
    fn from(_cfg: AppConfig) -> Self {
        App { _cfg }
    }

    pub fn init(_cfg: AppConfig) {
        unsafe {
            ONCE.call_once(|| {
                APP = Some(App::from(_cfg));
            });
        }
    }

    pub fn instance() -> &'static App {
        unsafe { APP.as_ref().unwrap() }
    }

    pub fn info(&self) -> String {
        self._cfg.db_path.clone()
    }
}
