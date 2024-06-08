use std::fmt;

#[derive(Debug)]
pub enum Error {
    // 无法正常创建/打开数据库
    CannotOpenDatabase(String, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::CannotOpenDatabase(ref path, ref err) => {
                write!(f, "Cannot open database: {}, err: {}", path, err)
            }
        }
    }
}
