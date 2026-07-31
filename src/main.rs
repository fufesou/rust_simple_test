use std::{env, num::NonZeroU16, process::ExitCode, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use ldap3::{drive, Ldap, LdapConnAsync, LdapConnSettings, Scope};

const CONNECTION_TIMEOUT_SECONDS: u64 = 6;
const DEFAULT_FILTER: &str = "(objectClass=*)";
const DEFAULT_PASSWORD_ENV: &str = "LDAP_PASSWORD";
const LDAP_PREFIX: &str = "ldap://";
const LDAPS_PREFIX: &str = "ldaps://";
const NO_ATTRIBUTES: &str = "1.1";

#[cfg(any(target_os = "windows", target_os = "macos"))]
const TLS_BACKEND: &str = "native-tls";
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const TLS_BACKEND: &str = "rustls";

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Diagnose LDAP, StartTLS, and LDAPS connections",
    after_help = "Set the bind password in LDAP_PASSWORD, or select another variable with --password-env. Passwords and LDAP entries are never printed."
)]
struct Cli {
    /// LDAP hostname or IP address, optionally prefixed with ldap:// or ldaps://
    #[arg(long, value_name = "HOST")]
    host: String,
    /// LDAP server port, normally 389 for LDAP/StartTLS or 636 for LDAPS
    #[arg(long, value_name = "PORT")]
    port: NonZeroU16,
    /// Base DN used for the diagnostic search
    #[arg(long, value_name = "DN")]
    base_dn: String,
    /// Search scope used for the diagnostic search
    #[arg(long, value_enum)]
    scope: SearchScope,
    /// Upgrade an ldap:// connection with StartTLS
    #[arg(long, conflicts_with = "ssl")]
    starttls: bool,
    /// Connect with LDAPS
    #[arg(long, conflicts_with = "starttls")]
    ssl: bool,
    /// Disable TLS certificate verification
    #[arg(long)]
    no_tls_verify: bool,
    /// Optional DN used for a simple bind
    #[arg(long, value_name = "DN")]
    bind_dn: Option<String>,
    /// Environment variable containing the bind password
    #[arg(long, value_name = "NAME", default_value = DEFAULT_PASSWORD_ENV)]
    password_env: String,
    /// LDAP search filter
    #[arg(long, default_value = DEFAULT_FILTER)]
    filter: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SearchScope {
    One,
    Sub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlsMode {
    Plain,
    StartTls,
    Ldaps,
}

impl TlsMode {
    fn scheme(self) -> &'static str {
        match self {
            Self::Plain | Self::StartTls => "ldap",
            Self::Ldaps => "ldaps",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ConnectionConfig {
    url: String,
    mode: TlsMode,
    starttls: bool,
    no_tls_verify: bool,
}

impl TryFrom<&Cli> for ConnectionConfig {
    type Error = anyhow::Error;

    fn try_from(cli: &Cli) -> Result<Self> {
        let (host_scheme, authority) = parse_host(&cli.host)?;
        let mode = resolve_tls_mode(cli, host_scheme)?;
        if cli.no_tls_verify && mode == TlsMode::Plain {
            bail!("--no-tls-verify requires --starttls, --ssl, or an ldaps:// host");
        }
        let url = format!("{}://{}:{}", mode.scheme(), authority, cli.port);
        Ok(Self {
            url,
            mode,
            starttls: mode == TlsMode::StartTls,
            no_tls_verify: cli.no_tls_verify,
        })
    }
}

fn parse_host(host: &str) -> Result<(Option<TlsMode>, &str)> {
    let host = host.trim().trim_end_matches('/');
    let lowercase = host.to_ascii_lowercase();
    let (scheme, authority) = if lowercase.starts_with(LDAP_PREFIX) {
        (Some(TlsMode::Plain), &host[LDAP_PREFIX.len()..])
    } else if lowercase.starts_with(LDAPS_PREFIX) {
        (Some(TlsMode::Ldaps), &host[LDAPS_PREFIX.len()..])
    } else if host.contains("://") {
        bail!("unsupported --host scheme; use ldap:// or ldaps://");
    } else {
        (None, host)
    };
    validate_host_authority(authority)?;
    Ok((scheme, authority))
}

fn validate_host_authority(authority: &str) -> Result<()> {
    if authority.is_empty() {
        bail!("--host cannot be empty");
    }
    if authority.contains('/') {
        bail!("--host must not contain a URL path");
    }
    if authority.contains(':') && !(authority.starts_with('[') && authority.ends_with(']')) {
        bail!("--host must not contain a port; use --port instead");
    }
    Ok(())
}

fn resolve_tls_mode(cli: &Cli, host_scheme: Option<TlsMode>) -> Result<TlsMode> {
    if cli.starttls && host_scheme == Some(TlsMode::Ldaps) {
        bail!("--starttls cannot be used with an ldaps:// host");
    }
    if cli.ssl && host_scheme == Some(TlsMode::Plain) {
        bail!("--ssl cannot be used with an ldap:// host");
    }
    if cli.starttls {
        return Ok(TlsMode::StartTls);
    }
    if cli.ssl || host_scheme == Some(TlsMode::Ldaps) {
        return Ok(TlsMode::Ldaps);
    }
    Ok(TlsMode::Plain)
}

fn validate_search_options(cli: &Cli) -> Result<()> {
    if cli.base_dn.trim().is_empty() {
        bail!("--base-dn cannot be empty");
    }
    if cli.filter.trim().is_empty() {
        bail!("--filter cannot be empty");
    }
    let empty_bind_dn = cli
        .bind_dn
        .as_deref()
        .is_some_and(|dn| dn.trim().is_empty());
    if empty_bind_dn {
        bail!("--bind-dn cannot be empty");
    }
    if cli.bind_dn.is_some() && cli.password_env.trim().is_empty() {
        bail!("--password-env cannot be empty when --bind-dn is set");
    }
    Ok(())
}

async fn connect(config: &ConnectionConfig) -> Result<Ldap> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECONDS))
        .set_starttls(config.starttls)
        .set_no_tls_verify(config.no_tls_verify);
    let (connection, ldap) = LdapConnAsync::with_settings(settings, &config.url)
        .await
        .with_context(|| format!("connect stage failed for {}", config.url))?;
    drive!(connection);
    Ok(ldap)
}

async fn bind_if_requested(ldap: &mut Ldap, cli: &Cli) -> Result<()> {
    let Some(bind_dn) = cli.bind_dn.as_deref() else {
        println!("BIND: skipped (anonymous search)");
        return Ok(());
    };
    let password = env::var(&cli.password_env)
        .with_context(|| format!("bind stage could not read {}", cli.password_env))?;
    ldap.simple_bind(bind_dn, &password)
        .await
        .context("bind stage request failed")?
        .success()
        .context("bind stage was rejected by the LDAP server")?;
    println!("BIND: success");
    Ok(())
}

async fn search_directory(ldap: &mut Ldap, cli: &Cli) -> Result<()> {
    let scope = match cli.scope {
        SearchScope::One => Scope::OneLevel,
        SearchScope::Sub => Scope::Subtree,
    };
    let (entries, _) = ldap
        .search(&cli.base_dn, scope, &cli.filter, vec![NO_ATTRIBUTES])
        .await
        .context("search stage request failed")?
        .success()
        .context("search stage was rejected by the LDAP server")?;
    println!("SEARCH: success ({} entries)", entries.len());
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    validate_search_options(&cli)?;
    let connection = ConnectionConfig::try_from(&cli)?;
    let tls_mode = match connection.mode {
        TlsMode::Plain => "plain LDAP",
        TlsMode::StartTls => "StartTLS",
        TlsMode::Ldaps => "LDAPS",
    };
    println!("URL: {}", connection.url);
    println!("TLS mode: {tls_mode}");
    println!("TLS backend: {TLS_BACKEND}");
    println!("Certificate verification: {}", !connection.no_tls_verify);
    let mut ldap = connect(&connection).await?;
    println!("CONNECT: success");
    bind_if_requested(&mut ldap, &cli).await?;
    search_directory(&mut ldap, &cli).await?;
    ldap.unbind().await.context("unbind stage failed")?;
    println!("UNBIND: success");
    Ok(())
}

fn report_error(error: &anyhow::Error) {
    eprintln!("LDAP diagnostic failed");
    for (index, cause) in error.chain().enumerate() {
        eprintln!("  cause[{index}]: {cause}");
    }
    eprintln!("  debug: {error:?}");
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn arguments(port: &'static str, extra: &[&'static str]) -> Vec<&'static str> {
        let mut args = vec![
            "simple_test",
            "--host",
            "ldap.example.com",
            "--port",
            port,
            "--base-dn",
            "dc=example,dc=com",
            "--scope",
            "sub",
        ];
        args.extend_from_slice(extra);
        args
    }

    #[test]
    fn parses_starttls_arguments() {
        let cli = Cli::try_parse_from(arguments("389", &["--starttls", "--no-tls-verify"]))
            .expect("StartTLS arguments should parse");
        let connection = ConnectionConfig::try_from(&cli).expect("StartTLS config should be valid");
        assert_eq!(connection.url, "ldap://ldap.example.com:389");
        assert!(connection.starttls);
        assert!(connection.no_tls_verify);
    }

    #[test]
    fn rejects_starttls_with_ssl() {
        let result = Cli::try_parse_from(arguments("389", &["--starttls", "--ssl"]));
        assert!(result.is_err());
    }

    #[test]
    fn builds_ldaps_url_for_ssl_mode() {
        let cli = Cli::try_parse_from(arguments("636", &["--ssl"]))
            .expect("LDAPS arguments should parse");
        let connection = ConnectionConfig::try_from(&cli).expect("LDAPS config should be valid");
        assert_eq!(connection.url, "ldaps://ldap.example.com:636");
    }
}
