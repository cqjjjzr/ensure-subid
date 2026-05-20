use std::ffi::CString;

pub(crate) fn log_warning(message: &str) {
    let sanitized = message.replace('\0', "\\0");

    let Ok(c_message) = CString::new(sanitized) else {
        return;
    };

    static IDENT: &[u8] = b"ensure-subid\0";
    static FMT: &[u8] = b"%s\0";

    // SAFETY: IDENT, FMT, and c_message are valid NUL-terminated strings.
    // syslog copies the message before returning and does not retain pointers.
    unsafe {
        libc::openlog(
            IDENT.as_ptr() as *const libc::c_char,
            libc::LOG_PID | libc::LOG_NDELAY,
            libc::LOG_AUTHPRIV,
        );

        libc::syslog(
            libc::LOG_WARNING,
            FMT.as_ptr() as *const libc::c_char,
            c_message.as_ptr(),
        );
    }
}
