use flutter_rust_bridge::frb;
use crate::app::app;

#[frb(init)]
pub fn init_app() {}

#[frb(sync)]
pub fn init(data_path: String) {
    app::App::init(data_path);
}

#[frb(sync)]
pub fn appinfo(name: String) -> String {
    format!("Hello, {name}!")
}
