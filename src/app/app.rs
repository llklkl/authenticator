use once_cell::sync::Lazy;

pub static APP: Lazy<App> = Lazy::new(App::new);

pub struct App {}

impl App {
    pub fn new() -> Self {
        App {}
    }

    pub fn hello(&self) -> String {
        String::from("hello rust")
    }
}
