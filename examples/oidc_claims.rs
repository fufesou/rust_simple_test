use log::LevelFilter;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreIdTokenVerifier, CoreJsonWebKey,
        CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreSubjectIdentifierType,
        CoreTokenIntrospectionResponse, CoreTokenType,
    },
    reqwest::http_client,
    url::Url,
    AdditionalProviderMetadata, AuthenticationFlow, AuthorizationCode, Client, ClientId,
    ClientSecret, CsrfToken, IdTokenClaims, IdTokenFields, IssuerUrl, Nonce, OAuth2TokenResponse,
    ProviderMetadata, RedirectUrl, RevocationUrl, Scope, StandardErrorResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    process::exit,
};
use structopt::{clap::AppSettings, StructOpt};

fn handle_error<T: std::error::Error>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&dyn std::error::Error> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\n    caused by: {}", cause);
        cur_fail = cause.source();
    }
    log::error!("{}", err_msg);
    exit(1);
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationEndpointProviderMetadata {
    revocation_endpoint: String,
}
impl AdditionalProviderMetadata for RevocationEndpointProviderMetadata {}
type OidcProviderMetadata = ProviderMetadata<
    RevocationEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct OidcAdditionalClaims {
    groups: Option<Vec<String>>,
    roles: Option<Vec<String>>,
}

impl openidconnect::AdditionalClaims for OidcAdditionalClaims {}

type OidcClient = Client<
    OidcAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OidcTokenResponse,
    CoreTokenType,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
>;

type OidcTokenFields = IdTokenFields<
    OidcAdditionalClaims,
    openidconnect::EmptyExtraTokenFields,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
    openidconnect::core::CoreJsonWebKeyType,
>;

type OidcTokenResponse =
    openidconnect::StandardTokenResponse<OidcTokenFields, openidconnect::core::CoreTokenType>;

#[derive(StructOpt, Debug)]
#[structopt(name = "oidc-test",
            about = "Test OpenID Connect and print claims",
            rename_all = "kebab-case",
            setting = AppSettings::ColoredHelp)]
struct Options {
    /// The log level. t - trace, d - debug, i - info, w - warn, e - error. Default is "d".
    #[structopt(long, short)]
    loglevel: Option<String>,

    /// The issuer URL.
    #[structopt(long, short = "I")]
    issuer: String,

    /// The client ID.
    #[structopt(long, short = "i")]
    client_id: String,

    /// The client secret.
    #[structopt(long, short = "s")]
    client_secret: String,

    /// callback port, default 18081
    #[structopt(long, short, default_value = "18081")]
    port: u16,
}

fn main() {
    let options = Options::from_args();

    let level = match options.loglevel.as_ref().unwrap_or(&String::from("i")) as &str {
        "t" => LevelFilter::Trace,
        "d" => LevelFilter::Debug,
        "i" => LevelFilter::Info,
        "w" => LevelFilter::Warn,
        "e" => LevelFilter::Error,
        _ => LevelFilter::Debug,
    };
    env_logger::builder().filter_level(level).init();

    log::info!("The options: {:?}", &options);

    log::info!("Please add the following redirect URL to your OIDC client configuration:");
    log::info!("  http://localhost:{}", options.port);
    log::info!("\n\nPress any key to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    let port = options.port;

    let client_id = ClientId::new(options.client_id);
    let client_secret = ClientSecret::new(options.client_secret);
    let issuer_url = IssuerUrl::new(options.issuer).unwrap();

    let provider_metadata = OidcProviderMetadata::discover(&issuer_url, http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        });
    let revocation_endpoint = provider_metadata
        .additional_metadata()
        .revocation_endpoint
        .clone();
    log::info!(
        "Discovered Oidc revocation endpoint: {}",
        revocation_endpoint
    );

    let client =
        OidcClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(
                RedirectUrl::new(format!("http://localhost:{}", port))
                    .expect("Invalid redirect URL"),
            )
            .set_revocation_uri(
                RevocationUrl::new(revocation_endpoint).expect("Invalid revocation endpoint URL"),
            );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("groups".to_string()))
        .url();

    log::info!("Open this URL in your browser:\n{}\n", authorize_url);

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();

    // Accept one connection
    let (mut stream, _) = listener.accept().unwrap();

    let code;
    let state;
    {
        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

        let code_pair = url
            .query_pairs()
            .find(|pair| {
                let &(ref key, _) = pair;
                key == "code"
            })
            .unwrap();

        let (_, value) = code_pair;
        code = AuthorizationCode::new(value.into_owned());

        let state_pair = url
            .query_pairs()
            .find(|pair| {
                let &(ref key, _) = pair;
                key == "state"
            })
            .unwrap();

        let (_, value) = state_pair;
        state = CsrfToken::new(value.into_owned());
    }

    let message = "Go back to your terminal :)";
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
        message.len(),
        message
    );
    stream.write_all(response.as_bytes()).unwrap();

    log::info!("Oidc returned the following code:\n{}\n", code.secret());
    log::info!(
        "Oidc returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    // Exchange the code with a token.
    let token_response = client
        .exchange_code(code)
        .request(http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to contact token endpoint");
            unreachable!();
        });

    log::info!(
        "Oidc returned access token:\n{}\n",
        token_response.access_token().secret()
    );
    log::info!("Oidc returned scopes: {:?}", token_response.scopes());

    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let id_token_claims: &IdTokenClaims<OidcAdditionalClaims, CoreGenderClaim> = token_response
        .extra_fields()
        .id_token()
        .expect("Server did not return an ID token")
        .claims(&id_token_verifier, &nonce)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to verify ID token");
            unreachable!();
        });
    log::info!("Oidc returned ID token: {:?}", id_token_claims);

    // Revoke the obtained token
    let token_to_revoke: CoreRevocableToken = match token_response.refresh_token() {
        Some(token) => token.into(),
        None => token_response.access_token().into(),
    };

    client
        .revoke_token(token_to_revoke)
        .expect("no revocation_uri configured")
        .request(http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to contact token revocation endpoint");
            unreachable!();
        });
}
