use crate::app::app;

pub fn hello() -> String {
    app::APP.hello()
}
