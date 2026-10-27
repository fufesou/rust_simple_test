use crate::{
    callback::Callback,
    claims,
    http::{self, TraceClient},
    report::Report,
};
use anyhow::{Context, Result};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata,
        CoreTokenResponse,
    },
    reqwest, ClientId, ClientSecret, CsrfToken, DiscoveryError, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl,
    RequestTokenError, Scope, TokenResponse, UserInfoClaims, UserInfoError, UserInfoUrl,
};
use serde_json::Value;
use std::io;

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
type Transport<'a> = (&'a reqwest::blocking::Client, &'a Report);

pub fn discover(
    issuer: &IssuerUrl,
    override_url: Option<UserInfoUrl>,
    transport: Transport<'_>,
) -> Result<CoreProviderMetadata> {
    let (http, report) = transport;
    report.line(format!("Issuer: {}", http::safe_url(issuer.url())))?;
    let trace = TraceClient::new(http, report, "discovery");
    let metadata = CoreProviderMetadata::discover(issuer, &trace).map_err(|error| {
        let detail = match error {
            DiscoveryError::Parse(error) => json_error(&error),
            DiscoveryError::Validation(_) => "issuer validation failed".into(),
            DiscoveryError::Request(_) => "HTTP request failed; see discovery stage".into(),
            DiscoveryError::Response(_, _, _) => {
                "unexpected HTTP response; see discovery stage".into()
            }
            _ => "discovery failed (details hidden)".into(),
        };
        anyhow::anyhow!("discovery: {detail}")
    })?;
    http::validate_endpoint(metadata.authorization_endpoint().url())?;
    http::validate_endpoint(
        metadata
            .token_endpoint()
            .context("token endpoint missing in discovery")?
            .url(),
    )?;
    select_userinfo(metadata, override_url, report)
}

fn select_userinfo(
    metadata: CoreProviderMetadata,
    override_url: Option<UserInfoUrl>,
    report: &Report,
) -> Result<CoreProviderMetadata> {
    if let Some(url) = metadata.userinfo_endpoint() {
        report.line(format!(
            "Discovered UserInfo: {}",
            http::safe_url(url.url())
        ))?;
    } else {
        report.line("Discovered UserInfo: absent")?;
    }
    let selected = override_url
        .as_ref()
        .or(metadata.userinfo_endpoint())
        .context("no UserInfo endpoint; supply --userinfo-endpoint")?;
    http::validate_endpoint(selected.url())?;
    report.line(format!(
        "Selected UserInfo: {} (source={})",
        http::safe_url(selected.url()),
        if override_url.is_some() {
            "override"
        } else {
            "discovery"
        }
    ))?;
    Ok(if override_url.is_some() {
        metadata.set_userinfo_endpoint(override_url)
    } else {
        metadata
    })
}

pub fn client(
    metadata: CoreProviderMetadata,
    secret: Option<ClientSecret>,
    identity: (&str, &str),
) -> Result<Client> {
    let redirect = RedirectUrl::new(identity.1.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid callback URL"))?;
    Ok(
        CoreClient::from_provider_metadata(metadata, ClientId::new(identity.0.to_owned()), secret)
            .set_redirect_uri(redirect),
    )
}

pub fn login(
    client: &Client,
    callback: &Callback,
    context: (&[String], &reqwest::blocking::Client, &Report),
) -> Result<()> {
    let (scopes, http, report) = context;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in scopes.iter().filter(|scope| scope.as_str() != "openid") {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    let (url, state, nonce) = request.url();
    report.line(format!("Callback: {}", callback.redirect))?;
    report.line("[authorization] Waiting for browser login; PKCE S256, state and nonce enabled")?;
    eprintln!("Open this URL locally (do not include it in the support report):\n{url}");
    let code = callback.wait(&state)?;
    report.line("[authorization] Callback state verified")?;
    let trace = TraceClient::new(http, report, "token");
    let response = client
        .exchange_code(code)
        .map_err(|_| anyhow::anyhow!("token endpoint missing in discovery"))?
        .set_pkce_verifier(verifier)
        .request(&trace);
    let payload = trace.take_payload();
    if let Some(token) = payload
        .as_ref()
        .and_then(|value| value.get("id_token"))
        .and_then(Value::as_str)
    {
        match claims::jwt_payload(token) {
            Ok(value) => describe(&value, "ID token (unverified raw claim types)", report)?,
            Err(error) => report.line(format!("[token] ID token diagnostics: {error}"))?,
        }
    }
    let token = response.map_err(|error| token_error(error, payload.as_ref()))?;
    verify_and_fetch(client, (&token, &nonce), (http, report))
}

fn verify_and_fetch(
    client: &Client,
    credentials: (&CoreTokenResponse, &Nonce),
    transport: Transport<'_>,
) -> Result<()> {
    let (token, nonce) = credentials;
    let (http, report) = transport;
    let id_token = token.id_token().context("token response has no ID token")?;
    let id_claims = id_token
        .claims(&client.id_token_verifier(), nonce)
        .map_err(|error| anyhow::anyhow!("ID token: {}", claims::verification_error(&error)))?;
    report.line("[token] ID token signature, issuer, audience, expiry and nonce verified")?;
    let trace = TraceClient::new(http, report, "userinfo");
    let response: Result<UserInfoClaims<claims::ExtraClaims, CoreGenderClaim>, _> = client
        .user_info(
            token.access_token().clone(),
            Some(id_claims.subject().clone()),
        )
        .map_err(|_| anyhow::anyhow!("UserInfo endpoint missing"))?
        .request(&trace);
    let payload = trace.take_payload();
    if let Some(value) = &payload {
        describe(value, "UserInfo (raw claim types; diagnostic only)", report)?;
    }
    response.map_err(|error| userinfo_error(error, payload.as_ref()))?;
    report.line("[userinfo] SDK parse and subject validation passed")?;
    Ok(())
}

fn describe(value: &Value, label: &str, report: &Report) -> io::Result<()> {
    report.line(label)?;
    for line in claims::summary(value) {
        report.line(line)?;
    }
    Ok(())
}

fn json_error(error: &serde_path_to_error::Error<serde_json::Error>) -> String {
    format!(
        "{}: JSON {:?} error at line {} column {} (value hidden)",
        claims::safe_path(error.path()),
        error.inner().classify(),
        error.inner().line(),
        error.inner().column()
    )
}

fn token_error(
    error: openidconnect::core::CoreRequestTokenError<io::Error>,
    payload: Option<&Value>,
) -> anyhow::Error {
    let detail = match error {
        RequestTokenError::Parse(error, _) => payload
            .and_then(claims::typed_error::<CoreTokenResponse>)
            .unwrap_or_else(|| json_error(&error)),
        RequestTokenError::ServerResponse(_) => "OAuth error; see token stage".into(),
        RequestTokenError::Request(_) => "HTTP request failed; see token stage".into(),
        _ => "token exchange failed (details hidden)".into(),
    };
    anyhow::anyhow!("token: {detail}")
}

fn userinfo_error(error: UserInfoError<io::Error>, payload: Option<&Value>) -> anyhow::Error {
    let detail = match error {
        UserInfoError::Parse(error) => payload
            .and_then(claims::userinfo_error)
            .unwrap_or_else(|| json_error(&error)),
        UserInfoError::ClaimsVerification(error) => claims::verification_error(&error).into(),
        UserInfoError::Request(_) => "HTTP request failed; see userinfo stage".into(),
        UserInfoError::Response(_, _, _) => "unexpected HTTP response; see userinfo stage".into(),
        _ => "UserInfo failed (details hidden)".into(),
    };
    anyhow::anyhow!("userinfo: {detail}")
}
