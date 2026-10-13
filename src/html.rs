use std::fmt;

use ego_tree::NodeRef;
use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE, WINDOWS_1252};
use html5ever::ParseOpts;
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tokenizer::{BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer};
use html5ever::tree_builder::TreeBuilderOpts;
use icu_properties::{CodePointSetData, props};
use scraper::{Html, HtmlTreeSink, Node, Selector};
use url::Url;

use crate::analyzer::Analyzer;
use crate::url_key::UrlKey;

pub const HTML_SCHEMA_ID: &str = "ley-html-v1";
pub const MAX_COMPRESSED_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DECODED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_HTML_EVENTS: usize = 250_000;
pub const MAX_HTML_DEPTH: usize = 256;
pub const MAX_TITLE_BYTES: usize = 4096;
pub const MAX_FIELDS_BYTES: usize = 1024 * 1024;
pub const MAX_DOCUMENT_TOKENS: usize = 100_000;
pub const MAX_OUTGOING_LINKS: usize = 5000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedDocument {
    pub requested_url: UrlKey,
    pub effective_url: String,
    pub title: String,
    pub body: String,
    pub links: Vec<UrlKey>,
    pub duplicate_links: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HtmlError {
    TooManyBytes { limit: usize },
    UnsupportedMediaType,
    UnsupportedContentEncoding,
    ParserEventLimit,
    NestingLimit,
    TitleLimit,
    FieldLimit,
    TokenLimit,
    InvalidEffectiveUrl,
}

impl fmt::Display for HtmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyBytes { limit } => write!(f, "HTML response exceeds {limit} bytes"),
            Self::UnsupportedMediaType => f.write_str("response media type is not text/html"),
            Self::UnsupportedContentEncoding => {
                f.write_str("compressed HTTP response encodings are unsupported")
            }
            Self::ParserEventLimit => {
                write!(f, "HTML parser event limit {MAX_HTML_EVENTS} exceeded")
            }
            Self::NestingLimit => write!(f, "HTML nesting limit {MAX_HTML_DEPTH} exceeded"),
            Self::TitleLimit => write!(f, "HTML title exceeds {MAX_TITLE_BYTES} UTF-8 bytes"),
            Self::FieldLimit => write!(f, "normalized HTML fields exceed {MAX_FIELDS_BYTES} bytes"),
            Self::TokenLimit => write!(f, "document exceeds {MAX_DOCUMENT_TOKENS} analyzer tokens"),
            Self::InvalidEffectiveUrl => f.write_str("effective URL is invalid"),
        }
    }
}

impl std::error::Error for HtmlError {}

pub fn extract_html(
    bytes: &[u8],
    content_type: &str,
    content_encoding: Option<&str>,
    requested_url: UrlKey,
    effective_url: &str,
) -> Result<ExtractedDocument, HtmlError> {
    if bytes.len() > MAX_COMPRESSED_RESPONSE_BYTES {
        return Err(HtmlError::TooManyBytes {
            limit: MAX_COMPRESSED_RESPONSE_BYTES,
        });
    }
    if content_encoding.is_some_and(|value| !value.eq_ignore_ascii_case("identity")) {
        return Err(HtmlError::UnsupportedContentEncoding);
    }
    let parsed_type = content_type
        .parse::<mime::Mime>()
        .map_err(|_| HtmlError::UnsupportedMediaType)?;
    if parsed_type.type_() != mime::TEXT || parsed_type.subtype() != mime::HTML {
        return Err(HtmlError::UnsupportedMediaType);
    }

    let encoding = determine_encoding(bytes, &parsed_type);
    let (decoded, _) = encoding.decode_with_bom_removal(bytes);
    if decoded.len() > MAX_DECODED_RESPONSE_BYTES {
        return Err(HtmlError::TooManyBytes {
            limit: MAX_DECODED_RESPONSE_BYTES,
        });
    }
    let decoded = decoded.into_owned();
    enforce_event_limit(&decoded)?;
    let document = parse_html(&decoded);
    enforce_tree_depth(&document)?;

    let title_selector =
        Selector::parse("head title").map_err(|_| HtmlError::UnsupportedMediaType)?;
    let title = document
        .select(&title_selector)
        .next()
        .map(|element| collapse_white_space(&element.text().collect::<String>()))
        .unwrap_or_default();
    if title.len() > MAX_TITLE_BYTES {
        return Err(HtmlError::TitleLimit);
    }

    let body_selector = Selector::parse("body").map_err(|_| HtmlError::UnsupportedMediaType)?;
    let body = document
        .select(&body_selector)
        .next()
        .map(extract_body)
        .unwrap_or_default();
    if title.len().saturating_add(body.len()) > MAX_FIELDS_BYTES {
        return Err(HtmlError::FieldLimit);
    }
    let analyzer = Analyzer;
    let token_count = analyzer
        .analyze(&title)
        .map_err(|_| HtmlError::TokenLimit)?
        .len()
        .saturating_add(
            analyzer
                .analyze(&body)
                .map_err(|_| HtmlError::TokenLimit)?
                .len(),
        );
    if token_count > MAX_DOCUMENT_TOKENS {
        return Err(HtmlError::TokenLimit);
    }

    let effective = Url::parse(effective_url).map_err(|_| HtmlError::InvalidEffectiveUrl)?;
    let base = find_base(&document, &effective);
    let (links, duplicate_links) = extract_links(&document, &base);

    Ok(ExtractedDocument {
        requested_url,
        effective_url: effective.to_string(),
        title,
        body,
        links,
        duplicate_links,
    })
}

fn determine_encoding(bytes: &[u8], content_type: &mime::Mime) -> &'static Encoding {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return UTF_8;
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return UTF_16BE;
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return UTF_16LE;
    }

    if let Some(label) = content_type.get_param("charset")
        && let Some(encoding) = Encoding::for_label(label.as_str().as_bytes())
    {
        return encoding;
    }

    if let Some(encoding) = sniff_meta_encoding(bytes) {
        return encoding;
    }
    WINDOWS_1252
}

fn sniff_meta_encoding(bytes: &[u8]) -> Option<&'static Encoding> {
    let prefix = &bytes[..bytes.len().min(1024)];
    if prefix.starts_with(b"<\0?\0x\0") {
        return Some(UTF_16LE);
    }
    if prefix.starts_with(b"\0<\0?\0x") {
        return Some(UTF_16BE);
    }
    let mut position = 0usize;
    while position < prefix.len() {
        if prefix[position..].starts_with(b"<!--") {
            if let Some(end) = find_bytes(&prefix[position..], b"-->") {
                position += end + 3;
                continue;
            }
            return sniff_xml_encoding(prefix);
        }
        if is_meta_start(prefix, position) {
            position += 5;
            let mut attributes = std::collections::BTreeSet::new();
            let mut got_pragma = false;
            let mut need_pragma = None;
            let mut charset = None;
            while let Some((name, value)) = scan_prescan_attribute(prefix, &mut position) {
                if !attributes.insert(name.clone()) {
                    continue;
                }
                match name.as_slice() {
                    b"http-equiv" if value.eq_ignore_ascii_case(b"content-type") => {
                        got_pragma = true;
                    }
                    b"content" if charset.is_none() => {
                        if let Some(encoding) = extract_meta_charset(&value) {
                            charset = Some(Some(encoding));
                            need_pragma = Some(true);
                        }
                    }
                    b"charset" => {
                        charset = Some(encoding_for_label(&value));
                        need_pragma = Some(false);
                    }
                    _ => {}
                }
            }
            if let (Some(need_pragma), Some(Some(encoding))) = (need_pragma, charset)
                && (!need_pragma || got_pragma)
            {
                return Some(meta_encoding(encoding));
            }
            position = position.saturating_add(1);
            continue;
        }
        if begins_ascii_tag(prefix, position) {
            while position < prefix.len()
                && !is_ascii_space(prefix[position])
                && prefix[position] != b'>'
            {
                position += 1;
            }
            while scan_prescan_attribute(prefix, &mut position).is_some() {}
            position = position.saturating_add(1);
            continue;
        }
        if prefix[position..].starts_with(b"<!")
            || prefix[position..].starts_with(b"</")
            || prefix[position..].starts_with(b"<?")
        {
            if let Some(end) = prefix[position..].iter().position(|byte| *byte == b'>') {
                position += end + 1;
                continue;
            }
            return sniff_xml_encoding(prefix);
        }
        position += 1;
    }
    sniff_xml_encoding(prefix)
}

fn is_meta_start(input: &[u8], position: usize) -> bool {
    input.get(position) == Some(&b'<')
        && input
            .get(position + 1..position + 5)
            .is_some_and(|name| name.eq_ignore_ascii_case(b"meta"))
        && input
            .get(position + 5)
            .is_some_and(|next| is_ascii_space(*next) || *next == b'/')
}

fn begins_ascii_tag(input: &[u8], position: usize) -> bool {
    if input.get(position) != Some(&b'<') {
        return false;
    }
    let mut name_position = position + 1;
    if input.get(name_position) == Some(&b'/') {
        name_position += 1;
    }
    input
        .get(name_position)
        .is_some_and(u8::is_ascii_alphabetic)
}

fn scan_prescan_attribute(input: &[u8], position: &mut usize) -> Option<(Vec<u8>, Vec<u8>)> {
    while input
        .get(*position)
        .is_some_and(|byte| is_ascii_space(*byte) || *byte == b'/')
    {
        *position += 1;
    }
    if input.get(*position).is_none_or(|byte| *byte == b'>') {
        return None;
    }
    let mut name = Vec::new();
    loop {
        let byte = *input.get(*position)?;
        if byte == b'=' && !name.is_empty() {
            *position += 1;
            break;
        }
        if is_ascii_space(byte) {
            while input
                .get(*position)
                .is_some_and(|byte| is_ascii_space(*byte))
            {
                *position += 1;
            }
            if input.get(*position) == Some(&b'=') {
                *position += 1;
                break;
            }
            return Some((name, Vec::new()));
        }
        if byte == b'/' || byte == b'>' {
            return Some((name, Vec::new()));
        }
        name.push(byte.to_ascii_lowercase());
        *position += 1;
    }
    while input
        .get(*position)
        .is_some_and(|byte| is_ascii_space(*byte))
    {
        *position += 1;
    }
    let first = *input.get(*position)?;
    let mut value = Vec::new();
    if first == b'"' || first == b'\'' {
        *position += 1;
        loop {
            let byte = *input.get(*position)?;
            *position += 1;
            if byte == first {
                return Some((name, value));
            }
            value.push(byte.to_ascii_lowercase());
        }
    }
    while let Some(byte) = input.get(*position).copied() {
        if is_ascii_space(byte) || byte == b'>' {
            break;
        }
        value.push(byte.to_ascii_lowercase());
        *position += 1;
    }
    Some((name, value))
}

fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn encoding_for_label(label: &[u8]) -> Option<&'static Encoding> {
    if label.eq_ignore_ascii_case(b"x-user-defined") {
        Some(WINDOWS_1252)
    } else {
        Encoding::for_label(label)
    }
}

fn extract_meta_charset(content: &[u8]) -> Option<&'static Encoding> {
    let mut search_from = 0;
    while let Some(relative) = content
        .get(search_from..)?
        .windows(b"charset".len())
        .position(|window| window.eq_ignore_ascii_case(b"charset"))
    {
        let start = search_from + relative;
        let mut position = start + b"charset".len();
        while content
            .get(position)
            .is_some_and(|byte| is_ascii_space(*byte))
        {
            position += 1;
        }
        if content.get(position) != Some(&b'=') {
            search_from = position.max(start + 1);
            continue;
        }
        position += 1;
        while content
            .get(position)
            .is_some_and(|byte| is_ascii_space(*byte))
        {
            position += 1;
        }
        let first = *content.get(position)?;
        let label = if first == b'"' || first == b'\'' {
            position += 1;
            let end = content[position..].iter().position(|byte| *byte == first)? + position;
            search_from = end + 1;
            &content[position..end]
        } else {
            let end = content[position..]
                .iter()
                .position(|byte| is_ascii_space(*byte) || *byte == b';')
                .map_or(content.len(), |relative| position + relative);
            search_from = end.max(position + 1);
            &content[position..end]
        };
        if let Some(encoding) = encoding_for_label(label) {
            return Some(encoding);
        }
    }
    None
}

fn sniff_xml_encoding(bytes: &[u8]) -> Option<&'static Encoding> {
    if !bytes.starts_with(b"<?xml") {
        return None;
    }
    let end = bytes.iter().position(|byte| *byte == b'>')?;
    let declaration = &bytes[..end];
    let mut position = declaration
        .windows(b"encoding".len())
        .position(|window| window == b"encoding")?
        + b"encoding".len();
    while declaration.get(position).is_some_and(|byte| *byte <= 0x20) {
        position += 1;
    }
    if declaration.get(position) != Some(&b'=') {
        return None;
    }
    position += 1;
    while declaration.get(position).is_some_and(|byte| *byte <= 0x20) {
        position += 1;
    }
    let quote = *declaration.get(position)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    position += 1;
    let value_end = declaration[position..]
        .iter()
        .position(|byte| *byte == quote)?
        + position;
    let label = &declaration[position..value_end];
    if label.iter().any(|byte| *byte <= 0x20) {
        return None;
    }
    encoding_for_label(label).map(meta_encoding)
}

fn meta_encoding(encoding: &'static Encoding) -> &'static Encoding {
    if encoding == UTF_16LE || encoding == UTF_16BE {
        UTF_8
    } else {
        encoding
    }
}

fn parse_html(input: &str) -> Html {
    let options = ParseOpts {
        tree_builder: TreeBuilderOpts {
            scripting_enabled: false,
            ..TreeBuilderOpts::default()
        },
        ..ParseOpts::default()
    };
    html5ever::parse_document(HtmlTreeSink::new(Html::new_document()), options).one(input)
}

struct EventCounter {
    count: std::cell::Cell<usize>,
    exceeded: std::cell::Cell<bool>,
}

impl TokenSink for EventCounter {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        let count = self.count.get() + 1;
        self.count.set(count);
        if count > MAX_HTML_EVENTS {
            self.exceeded.set(true);
        }
        if let Token::TagToken(tag) = token
            && tag.kind == TagKind::StartTag
        {
            let raw_state = match tag.name.as_ref() {
                "title" | "textarea" => Some(html5ever::tokenizer::states::RawKind::Rcdata),
                "script" => Some(html5ever::tokenizer::states::RawKind::ScriptData),
                "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                    Some(html5ever::tokenizer::states::RawKind::Rawtext)
                }
                _ => None,
            };
            if let Some(state) = raw_state {
                return TokenSinkResult::RawData(state);
            }
        }
        TokenSinkResult::Continue
    }
}

fn enforce_event_limit(input: &str) -> Result<(), HtmlError> {
    let sink = EventCounter {
        count: std::cell::Cell::new(0),
        exceeded: std::cell::Cell::new(false),
    };
    let tokenizer = Tokenizer::new(sink, Default::default());
    let queue = BufferQueue::default();
    queue.push_back(StrTendril::from_slice(input));
    let _ = tokenizer.feed(&queue);
    tokenizer.end();
    if tokenizer.sink.exceeded.get() {
        Err(HtmlError::ParserEventLimit)
    } else {
        Ok(())
    }
}

fn enforce_tree_depth(document: &Html) -> Result<(), HtmlError> {
    let mut stack = vec![(document.tree.root(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_HTML_DEPTH {
            return Err(HtmlError::NestingLimit);
        }
        for child in node.children() {
            stack.push((child, depth + 1));
        }
    }
    Ok(())
}

fn extract_body(body: scraper::ElementRef<'_>) -> String {
    enum Visit<'a> {
        Node(NodeRef<'a, Node>, usize),
        Space,
    }
    let mut output = String::new();
    let mut stack = Vec::new();
    for child in body.children().rev() {
        stack.push(Visit::Node(child, 0));
    }
    while let Some(visit) = stack.pop() {
        match visit {
            Visit::Space => output.push(' '),
            Visit::Node(node, depth) => {
                if depth > MAX_HTML_DEPTH {
                    continue;
                }
                if let Some(text) = node.value().as_text() {
                    output.push_str(text);
                    continue;
                }
                let Some(element) = node.value().as_element() else {
                    continue;
                };
                let name = element.name.local.as_ref();
                if matches!(
                    name,
                    "head" | "title" | "script" | "style" | "template" | "noscript"
                ) {
                    continue;
                }
                if name == "br" {
                    output.push(' ');
                    continue;
                }
                let block = is_block_element(name);
                if block {
                    output.push(' ');
                    stack.push(Visit::Space);
                }
                for child in node.children().rev() {
                    stack.push(Visit::Node(child, depth + 1));
                }
            }
        }
    }
    collapse_white_space(&output)
}

fn is_block_element(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "body"
            | "caption"
            | "dd"
            | "details"
            | "dialog"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "menu"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "summary"
            | "table"
            | "tbody"
            | "td"
            | "tfoot"
            | "th"
            | "thead"
            | "tr"
            | "ul"
    )
}

fn collapse_white_space(input: &str) -> String {
    let white_space = CodePointSetData::new::<props::WhiteSpace>();
    let mut output = String::with_capacity(input.len());
    let mut pending_space = false;
    for ch in input.chars() {
        if white_space.contains(ch) {
            if !output.is_empty() {
                pending_space = true;
            }
        } else {
            if pending_space {
                output.push(' ');
                pending_space = false;
            }
            output.push(ch);
        }
    }
    output
}

fn find_base(document: &Html, effective: &Url) -> Url {
    let Ok(selector) = Selector::parse("base[href]") else {
        return effective.clone();
    };
    let Some(first) = document.select(&selector).next() else {
        return effective.clone();
    };
    let Some(href) = first.attr("href") else {
        return effective.clone();
    };
    let Ok(base) = effective.join(href) else {
        return effective.clone();
    };
    if base.scheme() == "data" || base.scheme() == "javascript" {
        effective.clone()
    } else {
        base
    }
}

fn extract_links(document: &Html, base: &Url) -> (Vec<UrlKey>, usize) {
    let Ok(selector) = Selector::parse("a[href], area[href]") else {
        return (Vec::new(), 0);
    };
    let mut links = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut duplicates = 0;
    for element in document.select(&selector) {
        let Some(href) = element.attr("href") else {
            continue;
        };
        let Ok(key) = UrlKey::resolve(base, href) else {
            continue;
        };
        if seen.insert(key.clone()) {
            links.push(key);
            if links.len() == MAX_OUTGOING_LINKS {
                break;
            }
        } else {
            duplicates += 1;
        }
    }
    (links, duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn matches_published_html_extraction_vectors() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/reference-v1.json"))
            .expect("published reference fixture is valid JSON");
        for vector in fixture["extraction_vectors"]
            .as_array()
            .expect("extraction vectors")
        {
            let input = vector["html"].as_str().expect("html");
            let effective = vector["effective_url"].as_str().expect("effective URL");
            let result = extract_html(
                input.as_bytes(),
                "text/html; charset=utf-8",
                None,
                UrlKey::parse(effective).unwrap(),
                effective,
            )
            .unwrap();
            assert_eq!(
                result.title,
                vector["title"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
            assert_eq!(
                result.body,
                vector["body"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
            let expected: Vec<&str> = vector["links"]
                .as_array()
                .unwrap()
                .iter()
                .map(|url| url.as_str().unwrap())
                .collect();
            let actual: Vec<&str> = result.links.iter().map(UrlKey::as_str).collect();
            assert_eq!(actual, expected, "{}", vector["id"]);
            if vector["id"] == "html5-fields-and-link-base" {
                assert_eq!(result.duplicate_links, 0);
            }
        }
    }

    #[test]
    fn rejects_compressed_responses_and_limits_fields_and_bytes() {
        let url = UrlKey::parse("http://127.0.0.1/").unwrap();
        assert_eq!(
            extract_html(
                b"<p>x</p>",
                "text/html",
                Some("gzip"),
                url.clone(),
                "http://127.0.0.1/"
            ),
            Err(HtmlError::UnsupportedContentEncoding)
        );
        let large = vec![b'a'; MAX_COMPRESSED_RESPONSE_BYTES + 1];
        assert!(matches!(
            extract_html(&large, "text/html", None, url.clone(), "http://127.0.0.1/"),
            Err(HtmlError::TooManyBytes {
                limit: MAX_COMPRESSED_RESPONSE_BYTES
            })
        ));
        let title = format!("<title>{}</title>", "x".repeat(MAX_TITLE_BYTES + 1));
        assert_eq!(
            extract_html(
                title.as_bytes(),
                "text/html",
                None,
                url,
                "http://127.0.0.1/"
            ),
            Err(HtmlError::TitleLimit)
        );
    }

    #[test]
    fn obeys_bom_header_and_meta_encoding_precedence() {
        let url = UrlKey::parse("http://127.0.0.1/").unwrap();
        let mut bom_html = vec![0xEF, 0xBB, 0xBF];
        bom_html.extend_from_slice("<title>café</title>".as_bytes());
        let from_bom = extract_html(
            &bom_html,
            "text/html; charset=windows-1252",
            None,
            url.clone(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(from_bom.title, "café");

        let latin1 = b"<meta charset=windows-1252><title>caf\xe9</title>";
        let from_meta =
            extract_html(latin1, "text/html", None, url.clone(), "http://127.0.0.1/").unwrap();
        assert_eq!(from_meta.title, "café");

        let from_header = extract_html(
            latin1,
            "text/html; charset=utf-8",
            None,
            url,
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_ne!(from_header.title, "café");
    }

    #[test]
    fn sniffs_meta_charset_with_the_bounded_byte_prescan() {
        let url = UrlKey::parse("http://127.0.0.1/").unwrap();
        let commented = b"<!-- <meta charset=utf-8> --><title>caf\xc3\xa9</title>";
        let from_default = extract_html(
            commented,
            "text/html",
            None,
            url.clone(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(from_default.title, "cafÃ©");

        let attribute_text = b"<html><head><title>caf\xc3\xa9</title></head><body><div data-x=\"<meta charset=utf-8>\"></div></body></html>";
        let ignores_attribute_text = extract_html(
            attribute_text,
            "text/html",
            None,
            url.clone(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(ignores_attribute_text.title, "cafÃ©");

        let pragma = b"<meta content='text/html; charset=utf-8' http-equiv='content-type'><title>caf\xc3\xa9</title>";
        let from_pragma =
            extract_html(pragma, "text/html", None, url.clone(), "http://127.0.0.1/").unwrap();
        assert_eq!(from_pragma.title, "café");

        let duplicate = b"<meta charset=windows-1252 charset=utf-8><title>caf\xc3\xa9</title>";
        let first_attribute_wins = extract_html(
            duplicate,
            "text/html",
            None,
            url.clone(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(first_attribute_wins.title, "cafÃ©");

        let after_limit = format!(
            "{}<meta charset=utf-8><title>café</title>",
            " ".repeat(1024)
        );
        let limited = extract_html(
            after_limit.as_bytes(),
            "text/html",
            None,
            url,
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(limited.title, "cafÃ©");

        let xml = b"<?xml version='1.0' encoding='windows-1252'?><html><head><title>caf\xe9</title></head></html>";
        let from_xml = extract_html(
            xml,
            "text/html",
            None,
            UrlKey::parse("http://127.0.0.1/").unwrap(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(from_xml.title, "café");

        let utf16_html = "<html><head><title>café</title></head><body>utf16</body></html>";
        let utf16_bytes: Vec<u8> = utf16_html
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut utf16_with_bom = vec![0xFF, 0xFE];
        utf16_with_bom.extend_from_slice(&utf16_bytes);
        let from_utf16_bom = extract_html(
            &utf16_with_bom,
            "text/html; charset=windows-1252",
            None,
            UrlKey::parse("http://127.0.0.1/").unwrap(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(from_utf16_bom.title, "café");
    }

    #[test]
    fn enforces_parser_depth_event_and_token_caps() {
        let url = UrlKey::parse("http://127.0.0.1/").unwrap();
        let nested = format!(
            "{}x{}",
            "<div>".repeat(MAX_HTML_DEPTH + 1),
            "</div>".repeat(MAX_HTML_DEPTH + 1)
        );
        assert_eq!(
            extract_html(
                nested.as_bytes(),
                "text/html",
                None,
                url.clone(),
                "http://127.0.0.1/"
            ),
            Err(HtmlError::NestingLimit)
        );

        let event_heavy = "<x></x>".repeat(MAX_HTML_EVENTS / 2 + 1);
        assert_eq!(
            extract_html(
                event_heavy.as_bytes(),
                "text/html",
                None,
                url.clone(),
                "http://127.0.0.1/"
            ),
            Err(HtmlError::ParserEventLimit)
        );

        let token_heavy = format!("<body>{}</body>", "alpha ".repeat(MAX_DOCUMENT_TOKENS + 1));
        assert_eq!(
            extract_html(
                token_heavy.as_bytes(),
                "text/html",
                None,
                url,
                "http://127.0.0.1/"
            ),
            Err(HtmlError::TokenLimit)
        );
    }

    #[test]
    fn stops_link_discovery_at_the_distinct_key_limit() {
        let mut html = String::from("<body>");
        for index in 0..=MAX_OUTGOING_LINKS {
            html.push_str(&format!("<a href='/p/{index}'></a>"));
        }
        html.push_str("</body>");
        let result = extract_html(
            html.as_bytes(),
            "text/html",
            None,
            UrlKey::parse("http://127.0.0.1/").unwrap(),
            "http://127.0.0.1/",
        )
        .unwrap();
        assert_eq!(result.links.len(), MAX_OUTGOING_LINKS);
    }
}
