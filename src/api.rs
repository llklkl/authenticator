use crate::app::app;

pub use app::AppConfig;

pub fn init(_cfg: AppConfig) {
    app::App::init(_cfg);
}

pub fn info() -> String {
    app::App::instance().info()
}
