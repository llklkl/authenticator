use flutter_rust_bridge::frb;
use crate::app::app::App;
use crate::app::errors;

#[frb(init)]
pub fn init_app() {}

pub async fn init(data_path: String) -> Result<(), errors::Error> {
    App::init(data_path).await
}

#[frb(sync)]
pub fn appinfo(name: String) -> String {
    format!("Hello, {name}! dbname: {}", App::instance().appinfo())
}
