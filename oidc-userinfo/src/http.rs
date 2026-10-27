use crate::{
    claims,
    report::{oauth_error, Report},
};
use openidconnect::{
    reqwest, url::Url, HttpClientError, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde_json::Value;
use std::{cell::RefCell, io};

pub struct TraceClient<'a> {
    client: &'a reqwest::blocking::Client,
    report: &'a Report,
    stage: &'static str,
    payload: RefCell<Option<Value>>,
}

impl<'a> TraceClient<'a> {
    pub fn new(
        client: &'a reqwest::blocking::Client,
        report: &'a Report,
        stage: &'static str,
    ) -> Self {
        Self {
            client,
            report,
            stage,
            payload: RefCell::new(None),
        }
    }

    pub fn take_payload(&self) -> Option<Value> {
        self.payload.borrow_mut().take()
    }

    fn capture(&self, response: &HttpResponse) -> io::Result<()> {
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let mime = content_type.split(';').next().unwrap_or("");
        let kind = match mime.to_ascii_lowercase().as_str() {
            "application/json" => "JSON",
            "application/jwt" => "JWT",
            "text/html" => "HTML",
            "" => "missing",
            _ => "other",
        };
        self.report.line(format!(
            "[{}] HTTP {} Content-Type={kind}",
            self.stage,
            response.status().as_u16()
        ))?;
        match parse_body(response, kind) {
            Ok(value) => {
                if let Some(code) = value.get("error").and_then(Value::as_str) {
                    self.report.line(format!(
                        "[{}] OAuth error: {}",
                        self.stage,
                        oauth_error(code)
                    ))?;
                }
                *self.payload.borrow_mut() = Some(value);
            }
            Err(detail) => self
                .report
                .line(format!("[{}] Body diagnostics: {detail}", self.stage))?,
        }
        Ok(())
    }
}

impl SyncHttpClient for TraceClient<'_> {
    type Error = io::Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        *self.payload.borrow_mut() = None;
        let url = Url::parse(&request.uri().to_string())
            .map_err(|_| io::Error::other("invalid endpoint URL"))?;
        if let Err(error) = validate_endpoint(&url) {
            self.report
                .line(format!("[{}] Endpoint rejected: {error}", self.stage))?;
            return Err(error);
        }
        self.report.line(format!(
            "[{}] {} {}",
            self.stage,
            request.method(),
            safe_url(&url)
        ))?;
        let response = match self.client.call(request) {
            Ok(response) => response,
            Err(error) => {
                let detail = transport_error(&error);
                self.report
                    .line(format!("[{}] Transport error: {detail}", self.stage))?;
                return Err(io::Error::other(detail));
            }
        };
        self.capture(&response)?;
        Ok(response)
    }
}

pub fn validate_endpoint(url: &Url) -> io::Result<()> {
    let local = match url.host() {
        Some(openidconnect::url::Host::Domain("localhost")) => true,
        Some(openidconnect::url::Host::Ipv4(address)) => address.is_loopback(),
        Some(openidconnect::url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        return Err(io::Error::other(
            "endpoints require HTTPS (HTTP is allowed only on loopback)",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(io::Error::other(
            "endpoint URLs must not contain credentials",
        ));
    }
    Ok(())
}

pub fn safe_url(url: &Url) -> String {
    format!("{}{}", url.origin().ascii_serialization(), url.path())
}

fn parse_body(response: &HttpResponse, kind: &str) -> Result<Value, String> {
    if kind == "JWT" {
        return std::str::from_utf8(response.body())
            .map_err(|_| "invalid JWT encoding")
            .and_then(claims::jwt_payload)
            .map_err(str::to_owned);
    }
    serde_json::from_slice(response.body()).map_err(|error| {
        format!(
            "JSON {:?} error at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        )
    })
}

fn transport_error(error: &HttpClientError<reqwest::Error>) -> &'static str {
    match error {
        HttpClientError::Reqwest(error) if error.is_timeout() => "request timed out",
        HttpClientError::Reqwest(error) if error.is_connect() => "connection, DNS, or TLS failure",
        HttpClientError::Io(_) => "response I/O failure",
        _ => "HTTP request failed (details hidden)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_reject_credentials_and_allow_only_https_or_loopback_http() {
        for url in [
            "https://provider.example/userInfo",
            "http://127.0.0.1/userInfo",
            "http://[::1]/userInfo",
        ] {
            assert!(validate_endpoint(&Url::parse(url).unwrap()).is_ok());
        }
        for url in [
            "http://provider.example/userInfo",
            "https://private:secret@provider.example/userInfo",
        ] {
            assert!(validate_endpoint(&Url::parse(url).unwrap()).is_err());
        }
        let url =
            Url::parse("https://private:secret@provider.example/userInfo?token=private#private")
                .unwrap();
        assert_eq!(safe_url(&url), "https://provider.example/userInfo");
    }
}
