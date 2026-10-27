# OIDC UserInfo diagnostic

This standalone tool tests discovery, browser login, ID token verification and an actual UserInfo request. It uses the same pinned OpenID Connect SDK and `accept-string-booleans` feature as the RustDesk Server Pro fix. It does not change provider settings or revoke tokens.

## Customer test

1. Download and extract the archive for your OS and architecture from a `test-oidc-userinfo-*` release.
2. Run it on the computer where you will open the browser. Allow authorization code flow and register this exact callback URL on the OIDC client: `http://localhost:18081/callback`.
3. Set `OIDC_CLIENT_SECRET` locally for a confidential client. Leave it unset for a public client. Do not pass secrets as command-line arguments or send them to support.
4. Run the command below, replacing the issuer and client ID. Open the printed login URL in your browser, sign in, then return to the terminal.

For Cognito, the issuer is the user pool issuer (`https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID`), not the hosted UI domain. The selected scopes must be enabled for the app client.

Linux/macOS:

```sh
# Bash: read the secret without placing it in shell history.
read -r -s -p 'Client secret: ' OIDC_CLIENT_SECRET; echo
export OIDC_CLIENT_SECRET
./oidc-userinfo \
  --issuer 'https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID' \
  --client-id 'CLIENT_ID' \
  --report discovery-report.txt
unset OIDC_CLIENT_SECRET
```

For zsh, use `read -r -s 'OIDC_CLIENT_SECRET?Client secret: '` instead of the Bash `read` command. Skip the secret commands entirely for a public client.

Windows PowerShell:

```powershell
$secret = Read-Host 'Client secret' -AsSecureString
$env:OIDC_CLIENT_SECRET = [System.Net.NetworkCredential]::new('', $secret).Password
.\oidc-userinfo.exe --issuer 'https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID' --client-id 'CLIENT_ID' --report discovery-report.txt
Remove-Item Env:OIDC_CLIENT_SECRET
```

To test the configured UserInfo override, run again with a new report filename and add:

```text
--userinfo-endpoint https://your-proxy.example/userinfo --report override-report.txt
```

The override receives the access token, so use only your own trusted proxy. The report shows both the discovery endpoint and the selected endpoint, followed by the actual UserInfo request URL.

Other options: `--scopes openid,profile,email` (default; add `groups` only if supported), `--port 18081`, `--timeout-secs 300`, `--secret-env OTHER_VARIABLE`. Run `--help` for details. HTTP is allowed only for loopback endpoints; other endpoints require HTTPS. HTTP redirects are rejected. Tokens use HTTP Basic client authentication when a secret is set. Private CA certificates and alternative client authentication methods are not configured by this tool.

## What to send back

Send the saved report files and whether you tested discovery or an override. Do not send the browser URL, environment variables or complete terminal transcript.

Reports contain build provenance, endpoint host/path (queries and fragments omitted), HTTP status/content kind, verification stage, claim types, and safe parse-error field/type details. Only the verification flags' boolean values or exact `"true"`/`"false"` strings are shown. Other user claim values, tokens, authorization codes and client secrets are omitted. Review endpoint host/path information before sharing.

For example:

```text
ID token (unverified raw claim types)
  email_verified: boolean(true)
UserInfo (raw claim types; diagnostic only)
  email_verified: string(true); incompatible with a strict boolean parser
```

A `PASS` confirms verified ID token claims and successful UserInfo parsing with a matching subject using the compatible parser. It does not prove that an older RustDesk deployment is fixed. A failure exits with a nonzero status and identifies its stage. Raw claim-type diagnostics are not proof that a token is valid; the subsequent verification result is authoritative.

## Build and release

The package is independent of the repository's LDAP binary and native dependencies:

```sh
cargo +1.84 build --locked --release --manifest-path oidc-userinfo/Cargo.toml
```

The `OIDC UserInfo diagnostic` workflow builds Windows, Linux and macOS binaries for x64 and ARM64. Relevant branch pushes, pull requests and manual workflow runs produce downloadable Actions artifacts. Pushing a tag matching `test-oidc-userinfo-*` publishes a prerelease with archives, this README and SHA-256 checksums. The existing LDAP workflow excludes these tags.

CI compiles tests first, runs them with a 60-second timeout, and builds with the committed lockfile. No provider credentials are needed for these checks.
