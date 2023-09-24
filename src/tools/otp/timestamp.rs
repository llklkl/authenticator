use once_cell::sync::Lazy;
use simple_ntp::sntp;
use std::ops::{Add, Div};
use std::time;

struct TimeKeeper {
    t0: time::Instant,
    stdtime: time::Duration,
}

static T: Lazy<TimeKeeper> = Lazy::new(TimeKeeper::new);

impl TimeKeeper {
    fn new() -> Self {
        let t1 = time::Instant::now();
        let stdtime = Self::get_current_timestamp();
        let t2 = time::Instant::now();

        TimeKeeper {
            t0: t1.add(t2.duration_since(t1).div(2)),
            stdtime,
        }
    }

    pub fn now(&self) -> u64 {
        time::Instant::now()
            .duration_since(self.t0)
            .add(self.stdtime)
            .as_secs()
    }

    fn get_current_timestamp() -> time::Duration {
        sntp::unix_timestamp("ntp.aliyun.com")
            .ok()
            .unwrap_or(Self::sys_timestamp())
    }

    fn sys_timestamp() -> time::Duration {
        time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
    }
}

pub fn now() -> u64 {
    T.now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time};

    #[test]
    fn test_now() {
        println!("{:?}", sntp::unix_timestamp("ntp.aliyun.com"));
        println!("{}", now());
        thread::sleep(time::Duration::from_secs(2));
        println!("{}", now());
    }
}
