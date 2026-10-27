mod callback;
mod claims;
mod flow;
mod http;
mod report;

use anyhow::{bail, Context, Result};
use clap::Parser;
use openidconnect::{reqwest, ClientSecret, IssuerUrl, UserInfoUrl};
use report::Report;
use std::{
    num::{NonZeroU16, NonZeroU64},
    path::PathBuf,
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(
    version,
    about = "Diagnose OIDC discovery, login, and UserInfo with a redacted report"
)]
struct Options {
    /// Issuer URL, not the hosted login page URL
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    client_id: String,
    /// Replace the UserInfo endpoint advertised by discovery
    #[arg(long)]
    userinfo_endpoint: Option<String>,
    /// Environment variable containing the client secret; unset for a public client
    #[arg(long, default_value = "OIDC_CLIENT_SECRET")]
    secret_env: String,
    /// Comma-separated scopes; openid is required
    #[arg(long, value_delimiter = ',', default_value = "openid,profile,email")]
    scopes: Vec<String>,
    /// Register http://localhost:PORT/callback with the provider
    #[arg(long, default_value = "18081")]
    port: NonZeroU16,
    /// Timeout for each HTTP request and for the browser callback
    #[arg(long, default_value = "300")]
    timeout_secs: NonZeroU64,
    /// New report file; existing files are never overwritten
    #[arg(long)]
    report: Option<PathBuf>,
}

fn main() -> ExitCode {
    let options = Options::parse();
    let result = start(&options);
    if let Err(error) = result {
        eprintln!("ERROR: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn start(options: &Options) -> Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let path = options
        .report
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("oidc-report-{timestamp}.txt")));
    let report = Report::create(&path)
        .context("cannot create report; choose a new writable --report path")?;
    eprintln!("Share only the saved report: {}", path.display());
    report.line(format!(
        "oidc-userinfo {} build={} platform={}/{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("OIDC_BUILD_SHA").unwrap_or("local"),
        std::env::consts::OS,
        std::env::consts::ARCH
    ))?;
    report.line("Parser: openidconnect 3733415; accept-string-booleans enabled")?;
    let result = run(options, &report);
    match &result {
        Ok(()) => report
            .line("RESULT: PASS - ID token verified; UserInfo parsed with matching subject")?,
        Err(error) => report.line(format!("RESULT: FAIL - {error}"))?,
    }
    result
}

fn run(options: &Options, report: &Report) -> Result<()> {
    if !options.scopes.iter().any(|scope| scope == "openid")
        || options.scopes.iter().any(|scope| scope.is_empty())
    {
        bail!("--scopes must include openid and contain no empty entries");
    }
    let issuer = IssuerUrl::new(options.issuer.clone())
        .map_err(|_| anyhow::anyhow!("invalid issuer URL"))?;
    http::validate_endpoint(issuer.url())?;
    let override_url = options
        .userinfo_endpoint
        .as_ref()
        .map(|value| {
            let url = UserInfoUrl::new(value.clone())
                .map_err(|_| anyhow::anyhow!("invalid UserInfo URL"))?;
            http::validate_endpoint(url.url())?;
            Ok::<_, anyhow::Error>(url)
        })
        .transpose()?;
    let secret = match std::env::var(&options.secret_env) {
        Ok(value) if value.is_empty() => {
            bail!("client secret environment variable is empty; unset it for a public client")
        }
        Ok(value) => Some(ClientSecret::new(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => bail!("client secret environment variable is not valid Unicode"),
    };
    report.line(format!(
        "Client authentication: {}",
        if secret.is_some() {
            "client secret (HTTP Basic)"
        } else {
            "public client"
        }
    ))?;
    let timeout = Duration::from_secs(options.timeout_secs.get());
    let transport = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| anyhow::anyhow!("cannot initialize HTTP client"))?;
    let metadata = flow::discover(&issuer, override_url, (&transport, report))?;
    let callback = callback::Callback::bind(options.port.get(), timeout)?;
    let client = flow::client(metadata, secret, (&options.client_id, &callback.redirect))?;
    flow::login(&client, &callback, (&options.scopes, &transport, report))
}
