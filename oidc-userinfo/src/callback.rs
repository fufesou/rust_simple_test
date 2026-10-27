use crate::report::oauth_error;
use anyhow::{bail, Context, Result};
use openidconnect::{url::Url, AuthorizationCode, CsrfToken};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const READ_BUFFER_BYTES: usize = 1024;

pub struct Callback {
    listener: TcpListener,
    timeout: Duration,
    pub redirect: String,
}

impl Callback {
    pub fn bind(port: u16, timeout: Duration) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .context("cannot bind callback port; choose another --port")?;
        listener
            .set_nonblocking(true)
            .context("cannot configure callback listener")?;
        Ok(Self {
            listener,
            timeout,
            redirect: format!("http://localhost:{port}/callback"),
        })
    }

    pub fn wait(&self, state: &CsrfToken) -> Result<AuthorizationCode> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .context("callback timeout is too large")?;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("login callback timed out")?;
            match self.listener.accept() {
                Ok((stream, _)) => return receive(stream, deadline, state),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL_INTERVAL.min(remaining));
                }
                Err(_) => bail!("callback connection failed"),
            }
        }
    }
}

fn receive(
    mut stream: TcpStream,
    deadline: Instant,
    state: &CsrfToken,
) -> Result<AuthorizationCode> {
    stream
        .set_nonblocking(true)
        .context("cannot configure callback connection")?;
    let request = read_request(&mut stream, deadline)?;
    let result = parse_request(&request, state);
    stream
        .set_nonblocking(false)
        .context("cannot configure callback response")?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("callback timed out")?;
    stream
        .set_write_timeout(Some(remaining))
        .context("cannot set callback write timeout")?;
    let status = if result.is_ok() {
        "200 OK"
    } else {
        "400 Bad Request"
    };
    let body = "Return to the diagnostic terminal for the result.\n";
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        .context("cannot write callback response")?;
    result
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0; READ_BUFFER_BYTES];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("callback timed out")?;
        match stream.read(&mut buffer) {
            Ok(0) => bail!("callback connection closed before complete headers"),
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL.min(remaining));
                continue;
            }
            Err(_) => bail!("cannot read callback request"),
        }
        if bytes.len() > MAX_REQUEST_BYTES {
            bail!("callback headers exceed size limit");
        }
        if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| anyhow::anyhow!("callback request is not UTF-8"));
        }
    }
}

fn parse_request(request: &str, state: &CsrfToken) -> Result<AuthorizationCode> {
    let mut parts = request.split_whitespace();
    if parts.next() != Some("GET") {
        bail!("callback requires GET");
    }
    let path = parts.next().context("callback request target missing")?;
    if !path.starts_with("/callback?") {
        bail!("unexpected callback path");
    }
    let url = Url::parse(&format!("http://localhost{path}"))
        .map_err(|_| anyhow::anyhow!("invalid callback URL"))?;
    let pairs: Vec<_> = url.query_pairs().collect();
    let unique = |key: &str| -> Result<Option<String>> {
        let mut values = pairs.iter().filter(|(name, _)| name == key);
        let value = values.next().map(|(_, value)| value.to_string());
        if values.next().is_some() {
            bail!("duplicate callback parameter");
        }
        Ok(value)
    };
    if unique("state")?.as_deref() != Some(state.secret()) {
        bail!("callback state missing or mismatched");
    }
    if let Some(error) = unique("error")? {
        bail!("authorization failed: {}", oauth_error(&error));
    }
    let code = unique("code")?
        .filter(|value| !value.is_empty())
        .context("authorization code missing")?;
    Ok(AuthorizationCode::new(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_validates_state_and_hides_provider_values() {
        let state = CsrfToken::new("expected".into());
        assert!(parse_request("GET /callback?state=expected&code=secret HTTP/1.1", &state).is_ok());
        for path in [
            "?code=secret",
            "?state=wrong&code=secret",
            "?state=expected&state=expected&code=secret",
        ] {
            assert!(parse_request(&format!("GET /callback{path} HTTP/1.1"), &state).is_err());
        }
        let error = parse_request(
            "GET /callback?state=expected&error=private-data HTTP/1.1",
            &state,
        )
        .unwrap_err();
        assert!(!error.to_string().contains("private-data"));
    }
}
