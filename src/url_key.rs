use std::fmt;
use url::Url;

pub const MAX_URL_KEY_BYTES: usize = 2048;

/// Returns whether an encoded URL path falls within a slash-delimited scope.
/// Encoded separators, encoded percent signs, and encoded dot segments are
/// rejected so server-side decoding cannot widen the reviewed path scope.
pub(crate) fn path_is_within_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with('/')
        || !prefix.starts_with('/')
        || has_ambiguous_path_encoding(path)
        || has_ambiguous_path_encoding(prefix)
    {
        return false;
    }
    if prefix == "/" || prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn has_ambiguous_path_encoding(path: &str) -> bool {
    for segment in path.split('/') {
        let mut decoded = Vec::with_capacity(segment.len());
        let bytes = segment.as_bytes();
        let mut cursor = 0;
        while cursor < bytes.len() {
            if bytes[cursor] == b'%' {
                let Some(pair) = bytes.get(cursor + 1..cursor + 3) else {
                    return true;
                };
                let Some(high) = (pair[0] as char).to_digit(16) else {
                    return true;
                };
                let Some(low) = (pair[1] as char).to_digit(16) else {
                    return true;
                };
                let value = ((high << 4) | low) as u8;
                if matches!(value, b'/' | b'\\' | b'%') {
                    return true;
                }
                decoded.push(value);
                cursor += 3;
            } else {
                decoded.push(bytes[cursor]);
                cursor += 1;
            }
        }
        if decoded == b"." || decoded == b".." {
            return true;
        }
    }
    false
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct UrlKey(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UrlKeyError {
    InvalidUrl(String),
    UnsupportedScheme(String),
    UserInfo,
    MalformedPercentEscape,
    TooLong { bytes: usize },
}

impl fmt::Display for UrlKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) => write!(f, "invalid URL: {message}"),
            Self::UnsupportedScheme(scheme) => write!(f, "unsupported URL scheme: {scheme}"),
            Self::UserInfo => write!(f, "URL userinfo is not allowed"),
            Self::MalformedPercentEscape => write!(f, "URL has a malformed percent escape"),
            Self::TooLong { bytes } => write!(
                f,
                "URL key is {bytes} UTF-8 bytes; maximum is {MAX_URL_KEY_BYTES}"
            ),
        }
    }
}

impl std::error::Error for UrlKeyError {}

impl UrlKey {
    pub fn parse(input: &str) -> Result<Self, UrlKeyError> {
        let parsed =
            Url::parse(input).map_err(|error| UrlKeyError::InvalidUrl(error.to_string()))?;
        validate_parsed_url(&parsed)?;
        reject_raw_userinfo(input, None)?;
        Self::from_parsed(parsed)
    }

    fn from_parsed(mut parsed: Url) -> Result<Self, UrlKeyError> {
        validate_percent_escapes(parsed.path())?;
        if let Some(query) = parsed.query() {
            validate_percent_escapes(query)?;
        }
        parsed.set_fragment(None);
        let normalized = normalize_percent_escapes(parsed.as_str())?;
        if normalized.len() > MAX_URL_KEY_BYTES {
            return Err(UrlKeyError::TooLong {
                bytes: normalized.len(),
            });
        }
        Ok(Self(normalized))
    }

    pub fn resolve(base: &Url, reference: &str) -> Result<Self, UrlKeyError> {
        validate_reference_percent_escapes(reference)?;
        reject_raw_userinfo(reference, Some(base))?;
        let parsed = base
            .join(reference)
            .map_err(|error| UrlKeyError::InvalidUrl(error.to_string()))?;
        validate_parsed_url(&parsed)?;
        Self::from_parsed(parsed)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_url(&self) -> Result<Url, UrlKeyError> {
        Url::parse(&self.0).map_err(|error| UrlKeyError::InvalidUrl(error.to_string()))
    }
}

impl fmt::Display for UrlKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn validate_parsed_url(parsed: &Url) -> Result<(), UrlKeyError> {
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(UrlKeyError::UnsupportedScheme(scheme));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(UrlKeyError::UserInfo);
    }
    Ok(())
}

fn reject_raw_userinfo(raw_reference: &str, base: Option<&Url>) -> Result<(), UrlKeyError> {
    const PROBE: &str = "x";
    if !raw_reference.contains('@') {
        return Ok(());
    }
    let probed_reference = raw_reference.replace('@', "x@");
    let probed_url = match base {
        Some(base) => base.join(&probed_reference),
        None => Url::parse(&probed_reference),
    };
    if probed_url.is_ok_and(|url| {
        url.username().contains(PROBE)
            || url
                .password()
                .is_some_and(|password| password.contains(PROBE))
    }) {
        Err(UrlKeyError::UserInfo)
    } else {
        Ok(())
    }
}

fn validate_percent_escapes(value: &str) -> Result<(), UrlKeyError> {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let pair = bytes
                .get(cursor + 1..cursor + 3)
                .ok_or(UrlKeyError::MalformedPercentEscape)?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return Err(UrlKeyError::MalformedPercentEscape);
            }
            cursor += 3;
        } else {
            cursor += 1;
        }
    }
    Ok(())
}

fn validate_reference_percent_escapes(reference: &str) -> Result<(), UrlKeyError> {
    let without_fragment = reference.split('#').next().unwrap_or_default();
    let (after_authority, has_authority) =
        if let Some((_, rest)) = without_fragment.split_once("://") {
            (rest, true)
        } else if let Some(rest) = without_fragment.strip_prefix("//") {
            (rest, true)
        } else {
            (without_fragment, false)
        };
    let path_query = if has_authority {
        after_authority
            .find(['/', '?'])
            .map(|position| &after_authority[position..])
            .unwrap_or_default()
    } else {
        after_authority
    };
    let (path, query) = path_query
        .split_once('?')
        .map_or((path_query, None), |(path, query)| (path, Some(query)));
    validate_percent_escapes(path)?;
    if let Some(query) = query {
        validate_percent_escapes(query)?;
    }
    Ok(())
}

fn normalize_percent_escapes(value: &str) -> Result<String, UrlKeyError> {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'%' {
            let ch = value[cursor..]
                .chars()
                .next()
                .ok_or(UrlKeyError::MalformedPercentEscape)?;
            output.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        let pair = bytes
            .get(cursor + 1..cursor + 3)
            .ok_or(UrlKeyError::MalformedPercentEscape)?;
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return Err(UrlKeyError::MalformedPercentEscape);
        }
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(UrlKeyError::MalformedPercentEscape)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(UrlKeyError::MalformedPercentEscape)?;
        let byte = ((high << 4) | low) as u8;
        if is_unreserved(byte) {
            output.push(byte as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        cursor += 3;
    }
    Ok(output)
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn matches_all_published_url_vectors() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/reference-v1.json"))
            .expect("published reference fixture is valid JSON");
        for vector in fixture["url_vectors"].as_array().expect("url vectors") {
            let input = vector["input"].as_str().expect("input");
            if let Some(expected) = vector["expected"].as_str() {
                assert_eq!(UrlKey::parse(input).unwrap().as_str(), expected, "{input}");
            } else {
                let error = UrlKey::parse(input).unwrap_err();
                let expected = vector["error"].as_str().expect("error vector");
                let matched = matches!(
                    (expected, error),
                    (
                        "malformed_percent_escape",
                        UrlKeyError::MalformedPercentEscape
                    ) | ("userinfo", UrlKeyError::UserInfo)
                        | ("unsupported_scheme", UrlKeyError::UnsupportedScheme(_))
                );
                assert!(matched, "unexpected URL error for {input}");
            }
        }
    }

    #[test]
    fn rejects_userinfo_and_malformed_escapes_and_keeps_query_identity() {
        assert_eq!(
            UrlKey::parse("http://@127.0.0.1/x"),
            Err(UrlKeyError::UserInfo)
        );
        assert_eq!(
            UrlKey::parse("http://127.0.0.1/%GG"),
            Err(UrlKeyError::MalformedPercentEscape)
        );
        assert_ne!(
            UrlKey::parse("https://example.test/p?a=1&a=2").unwrap(),
            UrlKey::parse("https://example.test/p?a=2&a=1").unwrap()
        );
        assert_ne!(
            UrlKey::parse("https://example.test/p?x=").unwrap(),
            UrlKey::parse("https://example.test/p").unwrap()
        );
        let base = Url::parse("https://example.test/catalog/").unwrap();
        assert_eq!(
            UrlKey::resolve(&base, "child/%zz"),
            Err(UrlKeyError::MalformedPercentEscape)
        );

        let prefix = "https://example.test/";
        let at_limit = format!("{prefix}{}", "x".repeat(MAX_URL_KEY_BYTES - prefix.len()));
        assert_eq!(
            UrlKey::parse(&at_limit).unwrap().as_str().len(),
            MAX_URL_KEY_BYTES
        );
        let over_limit = format!("{at_limit}x");
        assert_eq!(
            UrlKey::parse(&over_limit),
            Err(UrlKeyError::TooLong {
                bytes: MAX_URL_KEY_BYTES + 1
            })
        );
    }

    #[test]
    fn path_scopes_require_segment_boundaries_and_reject_ambiguous_escapes() {
        for (path, prefix, expected) in [
            ("/public", "/public", true),
            ("/public/article", "/public", true),
            ("/public/article", "/public/", true),
            ("/publicity/article", "/public", false),
            ("/public%2fsecret", "/public", false),
            ("/public/%2e%2e/private", "/public/", false),
            ("/public/%252fsecret", "/public/", false),
            ("/private", "/public/", false),
            ("/private", "/", true),
        ] {
            assert_eq!(
                path_is_within_prefix(path, prefix),
                expected,
                "{path} under {prefix}"
            );
        }
    }

    #[test]
    fn rejects_userinfo_from_raw_whatwg_references_but_keeps_path_and_query_at_signs() {
        let base = Url::parse("http://127.0.0.1:12345/").unwrap();
        for reference in [
            "http://@127.0.0.1:12345/private",
            "//@127.0.0.1:12345/private",
            r"http:\\user@127.0.0.1:12345\private",
            r"\\@127.0.0.1:12345\private",
            "http:////@127.0.0.1:12345/private",
        ] {
            assert_eq!(
                UrlKey::resolve(&base, reference),
                Err(UrlKeyError::UserInfo),
                "{reference}"
            );
        }
        for input in [
            "http:user@127.0.0.1:12345/private",
            "http:/user@127.0.0.1:12345/private",
            r"http:\\user@127.0.0.1:12345\private",
            "http:@127.0.0.1:12345/private",
            "http:/@127.0.0.1:12345/private",
            r"http:\\@127.0.0.1:12345\private",
            "http:////@127.0.0.1:12345/private",
        ] {
            assert_eq!(UrlKey::parse(input), Err(UrlKeyError::UserInfo), "{input}");
        }

        for reference in [
            "/path@segment",
            "/path?next=@127.0.0.1:12345",
            "child/@segment?next=@host",
        ] {
            assert!(
                UrlKey::resolve(&base, reference).is_ok(),
                "literal path/query @ must remain valid: {reference}"
            );
        }
        assert_eq!(
            UrlKey::resolve(&base, "http:user@127.0.0.1:12345/private")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:12345/user@127.0.0.1:12345/private"
        );
        assert!(UrlKey::parse("http://127.0.0.1:12345/path@segment?next=@host").is_ok());
    }
}
