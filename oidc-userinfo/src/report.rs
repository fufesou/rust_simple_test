use std::{
    cell::RefCell,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

pub struct Report {
    file: RefCell<std::fs::File>,
}

impl Report {
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            const PRIVATE_FILE_MODE: u32 = 0o600;
            options.mode(PRIVATE_FILE_MODE);
        }
        Ok(Self {
            file: RefCell::new(options.open(path)?),
        })
    }

    pub fn line(&self, text: impl AsRef<str>) -> io::Result<()> {
        writeln!(self.file.borrow_mut(), "{}", text.as_ref())?;
        writeln!(io::stdout().lock(), "{}", text.as_ref())
    }
}

pub fn oauth_error(value: &str) -> &str {
    match value {
        "invalid_request"
        | "invalid_client"
        | "invalid_grant"
        | "unauthorized_client"
        | "unsupported_grant_type"
        | "invalid_scope"
        | "access_denied"
        | "server_error"
        | "temporarily_unavailable"
        | "unsupported_response_type"
        | "invalid_token"
        | "insufficient_scope"
        | "login_required"
        | "interaction_required" => value,
        _ => "unrecognized OAuth error (value hidden)",
    }
}
