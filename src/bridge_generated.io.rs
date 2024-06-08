use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_init(port_: i64, _cfg: *mut wire_AppConfig) {
    wire_init_impl(port_, _cfg)
}

#[no_mangle]
pub extern "C" fn wire_info(port_: i64) {
    wire_info_impl(port_)
}

// Section: allocate functions

#[no_mangle]
pub extern "C" fn new_box_autoadd_app_config_0() -> *mut wire_AppConfig {
    support::new_leak_box_ptr(wire_AppConfig::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_uint_8_list_0(len: i32) -> *mut wire_uint_8_list {
    let ans = wire_uint_8_list {
        ptr: support::new_leak_vec_ptr(Default::default(), len),
        len,
    };
    support::new_leak_box_ptr(ans)
}

// Section: related functions

// Section: impl Wire2Api

impl Wire2Api<String> for *mut wire_uint_8_list {
    fn wire2api(self) -> String {
        let vec: Vec<u8> = self.wire2api();
        String::from_utf8_lossy(&vec).into_owned()
    }
}
impl Wire2Api<AppConfig> for wire_AppConfig {
    fn wire2api(self) -> AppConfig {
        AppConfig {
            db_path: self.db_path.wire2api(),
        }
    }
}
impl Wire2Api<AppConfig> for *mut wire_AppConfig {
    fn wire2api(self) -> AppConfig {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<AppConfig>::wire2api(*wrap).into()
    }
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
    fn wire2api(self) -> Vec<u8> {
        unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        }
    }
}
// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_AppConfig {
    db_path: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
    ptr: *mut u8,
    len: i32,
}

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
    fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
    fn new_with_null_ptr() -> Self {
        std::ptr::null_mut()
    }
}

impl NewWithNullPtr for wire_AppConfig {
    fn new_with_null_ptr() -> Self {
        Self {
            db_path: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_AppConfig {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturn(ptr: support::WireSyncReturn) {
    unsafe {
        let _ = support::box_from_leak_ptr(ptr);
    };
}
