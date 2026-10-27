use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::{
    core::CoreGenderClaim, Audience, ClaimsVerificationError, IssuerUrl, StandardClaims,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_path_to_error::{Path, Segment};
use serde_value::DeserializerError;

const FIELDS: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "email",
    "email_verified",
    "phone_number_verified",
    "preferred_username",
    "groups",
    "upn",
    "unique_name",
    "address",
    "name",
    "exp",
    "iat",
    "nonce",
];

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ExtraClaims {
    groups: Option<Vec<String>>,
    upn: Option<String>,
    unique_name: Option<String>,
    email: Option<String>,
}

impl openidconnect::AdditionalClaims for ExtraClaims {}

#[derive(serde::Deserialize)]
struct Metadata<T> {
    #[serde(rename = "iss")]
    _issuer: Option<IssuerUrl>,
    #[serde(rename = "aud")]
    _audience: Option<T>,
}

pub fn jwt_payload(token: &str) -> Result<Value, &'static str> {
    let payload = token.split('.').nth(1).ok_or("JWT payload is missing")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "JWT payload is not valid base64url")?;
    serde_json::from_slice(&decoded).map_err(|_| "JWT payload is not valid JSON")
}

pub fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub fn summary(value: &Value) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return vec![format!("  root: {} (expected object)", kind(value))];
    };
    FIELDS
        .iter()
        .map(|field| {
            let Some(value) = object.get(*field) else {
                return format!("  {field}: absent");
            };
            let detail = match (*field, value) {
                ("email_verified" | "phone_number_verified", Value::Bool(flag)) => {
                    format!("boolean({flag})")
                }
                ("email_verified" | "phone_number_verified", Value::String(flag))
                    if flag == "true" || flag == "false" =>
                {
                    format!("string({flag}); incompatible with a strict boolean parser")
                }
                _ => format!("{} (value hidden)", kind(value)),
            };
            format!("  {field}: {detail}")
        })
        .collect()
}

pub fn safe_path(path: &Path) -> String {
    let mut result = String::new();
    for segment in path.iter() {
        match segment {
            Segment::Seq { index } => result.push_str(&format!("[{index}]")),
            Segment::Map { key } => {
                if !result.is_empty() {
                    result.push('.');
                }
                let field = key.split('#').next().unwrap_or("");
                let known = FIELDS.contains(&field)
                    || matches!(
                        field,
                        "postal_code"
                            | "street_address"
                            | "locality"
                            | "region"
                            | "country"
                            | "id_token"
                            | "access_token"
                            | "token_type"
                            | "expires_in"
                            | "refresh_token"
                            | "scope"
                            | "given_name"
                            | "family_name"
                            | "middle_name"
                            | "nickname"
                            | "profile"
                            | "picture"
                            | "website"
                            | "gender"
                            | "birthdate"
                            | "zoneinfo"
                            | "locale"
                            | "phone_number"
                            | "updated_at"
                    );
                result.push_str(if known { field } else { "<field>" });
            }
            _ => result.push_str("<field>"),
        }
    }
    if result.is_empty() {
        "<root>".into()
    } else {
        result
    }
}

pub fn typed_error<T: DeserializeOwned>(value: &Value) -> Option<String> {
    let value = match serde_value::to_value(value) {
        Ok(value) => value,
        Err(_) => return Some("diagnostic JSON conversion failed".into()),
    };
    let error = serde_path_to_error::deserialize::<_, T>(value).err()?;
    let detail = match error.inner() {
        DeserializerError::InvalidType(_, expected) => format!("invalid type, expected {expected}"),
        DeserializerError::InvalidValue(_, expected) => {
            format!("invalid value, expected {expected}")
        }
        DeserializerError::MissingField(field) => format!("missing field `{field}`"),
        _ => "invalid value (details hidden)".into(),
    };
    Some(format!("{}: {detail}", safe_path(error.path())))
}

pub fn userinfo_error(value: &Value) -> Option<String> {
    let metadata = if value.is_object() {
        if value.get("aud").is_some_and(Value::is_array) {
            typed_error::<Metadata<Vec<Audience>>>(value)
        } else {
            typed_error::<Metadata<Audience>>(value)
        }
    } else {
        None
    };
    metadata
        .or_else(|| typed_error::<StandardClaims<CoreGenderClaim>>(value))
        .or_else(|| typed_error::<ExtraClaims>(value))
}

pub fn verification_error(error: &ClaimsVerificationError) -> &'static str {
    match error {
        ClaimsVerificationError::Expired(_) => "token expired",
        ClaimsVerificationError::InvalidAudience(_) => "audience mismatch",
        ClaimsVerificationError::InvalidIssuer(_) => "issuer mismatch",
        ClaimsVerificationError::InvalidNonce(_) => "nonce mismatch",
        ClaimsVerificationError::InvalidSubject(_) => "subject mismatch",
        ClaimsVerificationError::SignatureVerification(_) => "signature verification failed",
        ClaimsVerificationError::InvalidAuthTime(_) => "authentication time invalid",
        _ => "claims verification failed (details hidden)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn claim_shapes_and_errors_preserve_types_without_private_values() {
        let value = json!({"sub":"private-subject", "email":"private@example.com",
            "email_verified":"true", "phone_number_verified":false, "groups":[987654321]});
        let output = format!(
            "{}\n{}",
            summary(&value).join("\n"),
            userinfo_error(&value).unwrap()
        );
        assert!(output.contains("email_verified: string(true)"));
        assert!(output.contains("phone_number_verified: boolean(false)"));
        assert!(output.contains("groups[0]: invalid type, expected a string"));
        assert!(!output.contains("private"));
        assert!(!output.contains("987654321"));
        assert!(userinfo_error(&json!([]))
            .unwrap()
            .contains("expected struct StandardClaims"));
    }

    #[test]
    fn raw_jwt_payload_is_only_used_for_redacted_type_diagnostics() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"private","email_verified":true}"#);
        let value = jwt_payload(&format!("header.{payload}.unverified-signature")).unwrap();
        let output = summary(&value).join("\n");
        assert!(output.contains("email_verified: boolean(true)"));
        assert!(!output.contains("private"));
        assert!(jwt_payload("invalid").is_err());
    }
}
