use crate::url_key::UrlKey;
use std::fmt;

pub const MAX_ROBOTS_BYTES: usize = 2 * 1024 * 1024;
const MAX_MATCH_WORK: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    TooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, maximum } => {
                write!(f, "robots input is {actual} bytes; maximum is {maximum}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug, Default)]
pub struct RobotsRules {
    groups: Vec<Group>,
}

#[derive(Clone, Debug, Default)]
struct Group {
    agents: Vec<Agent>,
    rules: Vec<Rule>,
    saw_rule_line: bool,
}

#[derive(Clone, Debug)]
enum Agent {
    Wildcard,
    Product(String),
}

#[derive(Clone, Debug)]
struct Rule {
    allow: bool,
    pattern: Pattern,
}

#[derive(Clone, Debug)]
struct Pattern {
    parts: Vec<PatternPart>,
    anchored: bool,
    literal_octets: usize,
}

#[derive(Clone, Debug)]
enum PatternPart {
    Literal(Vec<u8>),
    AnyMany,
}

pub fn parse_robots(input: &[u8]) -> Result<RobotsRules, ParseError> {
    if input.len() > MAX_ROBOTS_BYTES {
        return Err(ParseError::TooLarge {
            actual: input.len(),
            maximum: MAX_ROBOTS_BYTES,
        });
    }

    let mut groups = Vec::new();
    let mut current: Option<Group> = None;

    for raw_line in input.split(|byte| matches!(byte, b'\r' | b'\n')) {
        let Ok(raw_line) = std::str::from_utf8(raw_line) else {
            continue;
        };
        let uncommented = raw_line.split_once('#').map_or(raw_line, |(head, _)| head);
        let line = uncommented.trim_matches([' ', '\t']);
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim_matches([' ', '\t']);
        let value = value.trim_matches([' ', '\t']);

        if name.eq_ignore_ascii_case("user-agent") {
            if !is_valid_product_token(value) {
                continue;
            }

            if current.as_ref().is_some_and(|group| group.saw_rule_line) {
                groups.push(current.take().expect("checked as present"));
            }
            let group = current.get_or_insert_with(Group::default);
            if value == "*" {
                group.agents.push(Agent::Wildcard);
            } else {
                group.agents.push(Agent::Product(value.to_owned()));
            }
            continue;
        }

        if (name.eq_ignore_ascii_case("allow") || name.eq_ignore_ascii_case("disallow"))
            && let Some(group) = current.as_mut().filter(|group| !group.agents.is_empty())
        {
            if !value.is_empty()
                && (!value.starts_with('/')
                    || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f))
            {
                continue;
            }
            group.saw_rule_line = true;
            if !value.is_empty() {
                group.rules.push(Rule {
                    allow: name.eq_ignore_ascii_case("allow"),
                    pattern: Pattern::parse(value),
                });
            }
        }
    }

    if let Some(group) = current
        && !group.agents.is_empty()
    {
        groups.push(group);
    }

    Ok(RobotsRules { groups })
}

fn is_valid_product_token(value: &str) -> bool {
    value == "*"
        || (!value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'-' | b'_')))
}

impl RobotsRules {
    pub fn fetch_allowed(&self, product_token: &str, request_key: &UrlKey) -> bool {
        let Ok(url) = request_key.to_url() else {
            return false;
        };
        let mut request_target = url.path().to_owned();
        if let Some(query) = url.query() {
            request_target.push('?');
            request_target.push_str(query);
        }
        self.fetch_allowed_target(product_token, &request_target)
    }

    fn fetch_allowed_target(&self, product_token: &str, request_target: &str) -> bool {
        if request_target.len() > 2048 {
            return false;
        }
        let request = normalize_request_target(request_target);
        let mut exact_groups = Vec::new();
        let mut wildcard_groups = Vec::new();

        for group in &self.groups {
            let mut exact = false;
            let mut wildcard = false;
            for agent in &group.agents {
                match agent {
                    Agent::Wildcard => wildcard = true,
                    Agent::Product(name) if name.eq_ignore_ascii_case(product_token) => {
                        exact = true;
                    }
                    Agent::Product(_) => {}
                }
            }
            if exact {
                exact_groups.push(group);
            } else if wildcard {
                wildcard_groups.push(group);
            }
        }

        let selected = if exact_groups.is_empty() {
            wildcard_groups
        } else {
            exact_groups
        };

        let mut best: Option<(usize, bool)> = None;
        let mut work_left = MAX_MATCH_WORK;
        for rule in selected.into_iter().flat_map(|group| &group.rules) {
            let Some(matches) = rule.pattern.matches(&request, &mut work_left) else {
                return false;
            };
            if !matches {
                continue;
            }
            match best {
                None => best = Some((rule.pattern.literal_octets, rule.allow)),
                Some((specificity, _)) if rule.pattern.literal_octets > specificity => {
                    best = Some((rule.pattern.literal_octets, rule.allow));
                }
                Some((specificity, false))
                    if rule.pattern.literal_octets == specificity && rule.allow =>
                {
                    best = Some((specificity, true));
                }
                Some(_) => {}
            }
        }

        best.is_none_or(|(_, allowed)| allowed)
    }
}

impl Pattern {
    fn parse(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut parts = Vec::new();
        let mut literal = Vec::new();
        let mut anchored = false;
        let mut index = 0;
        let mut literal_octets = 0;

        while index < bytes.len() {
            match bytes[index] {
                b'*' => {
                    flush_literal(&mut parts, &mut literal);
                    if !matches!(parts.last(), Some(PatternPart::AnyMany)) {
                        parts.push(PatternPart::AnyMany);
                    }
                    index += 1;
                }
                b'$' if index + 1 == bytes.len() => {
                    anchored = true;
                    index += 1;
                }
                b'%' if index + 2 < bytes.len() => {
                    if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
                    {
                        let octet = (high << 4) | low;
                        if is_unreserved(octet) {
                            literal.push(octet);
                            literal_octets += 1;
                        } else {
                            push_escape(&mut literal, octet);
                            literal_octets += 3;
                        }
                        index += 3;
                    } else {
                        literal.extend_from_slice(b"%25");
                        literal_octets += 3;
                        index += 1;
                    }
                }
                byte if byte >= 0x80 => {
                    push_escape(&mut literal, byte);
                    literal_octets += 3;
                    index += 1;
                }
                byte => {
                    literal.push(byte);
                    literal_octets += 1;
                    index += 1;
                }
            }
        }
        flush_literal(&mut parts, &mut literal);

        Self {
            parts,
            anchored,
            literal_octets,
        }
    }

    fn matches(&self, request: &[u8], work_left: &mut usize) -> Option<bool> {
        let mut part_index = 0;
        let mut request_index = 0;
        let mut last_star: Option<(usize, usize)> = None;

        loop {
            *work_left = work_left.checked_sub(1)?;
            if part_index == self.parts.len() {
                if !self.anchored
                    || request_index == request.len()
                    || matches!(self.parts.last(), Some(PatternPart::AnyMany))
                {
                    return Some(true);
                }
                let Some((after_star, star_end)) = last_star else {
                    return Some(false);
                };
                if star_end >= request.len() {
                    return Some(false);
                }
                last_star = Some((after_star, star_end + 1));
                part_index = after_star;
                request_index = star_end + 1;
                continue;
            }

            match &self.parts[part_index] {
                PatternPart::AnyMany => {
                    last_star = Some((part_index + 1, request_index));
                    part_index += 1;
                }
                PatternPart::Literal(literal) => {
                    *work_left = work_left.checked_sub(literal.len())?;
                    if request[request_index..].starts_with(literal) {
                        request_index += literal.len();
                        part_index += 1;
                        continue;
                    }
                    let Some((after_star, star_end)) = last_star else {
                        return Some(false);
                    };
                    if star_end >= request.len() {
                        return Some(false);
                    }
                    let next = star_end + 1;
                    last_star = Some((after_star, next));
                    part_index = after_star;
                    request_index = next;
                }
            }
        }
    }
}

fn flush_literal(parts: &mut Vec<PatternPart>, literal: &mut Vec<u8>) {
    if literal.is_empty() {
        return;
    }
    parts.push(PatternPart::Literal(std::mem::take(literal)));
}

fn normalize_request_target(target: &str) -> Vec<u8> {
    let input = target.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        let byte = input[index];
        if byte == b'%'
            && index + 2 < input.len()
            && let (Some(high), Some(low)) = (hex(input[index + 1]), hex(input[index + 2]))
        {
            push_normalized_octet(&mut output, (high << 4) | low);
            index += 3;
            continue;
        }

        if byte >= 0x80
            || matches!(
                byte,
                b'*' | b'$' | b'%' | b' ' | b'"' | b'<' | b'>' | b'`' | b'{' | b'|' | b'}' | b'^'
            )
        {
            push_escape(&mut output, byte);
        } else {
            output.push(byte);
        }
        index += 1;
    }
    output
}

fn push_normalized_octet(output: &mut Vec<u8>, octet: u8) {
    if is_unreserved(octet) {
        output.push(octet);
    } else {
        push_escape(output, octet);
    }
}

fn push_escape(output: &mut Vec<u8>, octet: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.push(b'%');
    output.push(HEX[(octet >> 4) as usize]);
    output.push(HEX[(octet & 0x0f) as usize]);
}

fn is_unreserved(octet: u8) -> bool {
    octet.is_ascii_alphanumeric() || matches!(octet, b'-' | b'.' | b'_' | b'~')
}

fn hex(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet - b'0'),
        b'a'..=b'f' => Some(octet - b'a' + 10),
        b'A'..=b'F' => Some(octet - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ROBOTS_BYTES, RobotsRules, parse_robots};
    use crate::url_key::UrlKey;

    fn rules(body: &str) -> RobotsRules {
        parse_robots(body.as_bytes()).expect("fixture is under the parser size limit")
    }

    fn allowed(body: &str, token: &str, path: &str) -> bool {
        let key = UrlKey::parse(&format!("http://robots.fixture{path}"))
            .expect("robots fixture request has a valid URL key");
        rules(body).fetch_allowed(token, &key)
    }

    fn allowed_from(parsed: &RobotsRules, token: &str, path: &str) -> bool {
        let key = UrlKey::parse(&format!("http://robots.fixture{path}"))
            .expect("robots fixture request has a valid URL key");
        parsed.fetch_allowed(token, &key)
    }

    #[test]
    fn mandatory_fetch_decisions() {
        let cases = [
            (
                "case-insensitive product token",
                "User-agent: LeyBot\nDisallow: /private\n",
                "leybot",
                "/private/a",
                false,
            ),
            (
                "combine multiple exact groups",
                "User-agent: LeyBot\nDisallow: /one\n\nUser-agent: LeyBot\nDisallow: /two\n",
                "LeyBot",
                "/one/a",
                false,
            ),
            (
                "second exact group also applies",
                "User-agent: LeyBot\nDisallow: /one\n\nUser-agent: LeyBot\nDisallow: /two\n",
                "LeyBot",
                "/two/a",
                false,
            ),
            (
                "wildcard fallback applies",
                "User-agent: *\nDisallow: /general\n\nUser-agent: OtherBot\nDisallow: /special\n",
                "LeyBot",
                "/general/a",
                false,
            ),
            (
                "unrelated named group does not apply",
                "User-agent: *\nDisallow: /general\n\nUser-agent: OtherBot\nDisallow: /special\n",
                "LeyBot",
                "/special/a",
                true,
            ),
            (
                "longest path rule allows research",
                "User-agent: LeyBot\nDisallow: /private\nAllow: /private/research/\n",
                "LeyBot",
                "/private/research/a",
                true,
            ),
            (
                "shorter path rule still denies other private paths",
                "User-agent: LeyBot\nDisallow: /private\nAllow: /private/research/\n",
                "LeyBot",
                "/private/a",
                false,
            ),
            (
                "Allow wins equal specificity",
                "User-agent: LeyBot\nDisallow: /equal\nAllow: /equal\n",
                "LeyBot",
                "/equal/a",
                true,
            ),
            (
                "path match is case sensitive",
                "User-agent: LeyBot\nDisallow: /Case\n",
                "LeyBot",
                "/Case/a",
                false,
            ),
            (
                "lowercase path does not match uppercase rule",
                "User-agent: LeyBot\nDisallow: /Case\n",
                "LeyBot",
                "/case/a",
                true,
            ),
            (
                "wildcard and final end anchor match PDF",
                "User-agent: LeyBot\nDisallow: /*.pdf$\n",
                "LeyBot",
                "/a.pdf",
                false,
            ),
            (
                "end anchor excludes suffix",
                "User-agent: LeyBot\nDisallow: /*.pdf$\n",
                "LeyBot",
                "/a.pdf.txt",
                true,
            ),
            (
                "encoded unreserved ASCII is decoded",
                "User-agent: LeyBot\nDisallow: /bar\n",
                "LeyBot",
                "/%62ar",
                false,
            ),
            (
                "encoded reserved separator stays encoded",
                "User-agent: LeyBot\nDisallow: /foo%2Fbar\n",
                "LeyBot",
                "/foo%2Fbar",
                false,
            ),
            (
                "literal path separator differs from encoded separator",
                "User-agent: LeyBot\nDisallow: /foo%2Fbar\n",
                "LeyBot",
                "/foo/bar",
                true,
            ),
            (
                "UTF-8 request path matches percent-encoded rule",
                "User-agent: LeyBot\nDisallow: /caf%C3%A9\n",
                "LeyBot",
                "/café",
                false,
            ),
            (
                "encoded literal asterisk matches literal request asterisk",
                "User-agent: LeyBot\nDisallow: /path/%2A\n",
                "LeyBot",
                "/path/*",
                false,
            ),
            (
                "encoded literal asterisk is not wildcard",
                "User-agent: LeyBot\nDisallow: /path/%2A\n",
                "LeyBot",
                "/path/anything",
                true,
            ),
            (
                "comments and sitemap do not terminate group",
                "User-agent: LeyBot\nAllow: /open # comment\nSitemap: https://example.invalid/map.xml\nDisallow: /closed\n",
                "LeyBot",
                "/closed/a",
                false,
            ),
        ];

        for (name, body, token, path, expected) in cases {
            assert_eq!(allowed(body, token, path), expected, "{name}");
        }

        let body = "User-agent: LeyBot\nAllow: /open # comment\nSitemap: https://example.invalid/map.xml\nDisallow: /closed\n";
        assert!(allowed(body, "LeyBot", "/open/a"));
    }

    #[test]
    fn anchored_wildcards_backtrack_to_later_suffix_occurrences() {
        assert!(!allowed(
            "User-agent: LeyBot\nDisallow: /*foo$\n",
            "LeyBot",
            "/foofoo"
        ));
        assert!(!allowed(
            "User-agent: LeyBot\nDisallow: /*abab$\n",
            "LeyBot",
            "/ababaabab"
        ));
        assert!(allowed(
            "User-agent: LeyBot\nDisallow: /*foo$\n",
            "LeyBot",
            "/foofoo.txt"
        ));
        assert!(!allowed(
            "User-agent: LeyBot\nDisallow: /*foo\n",
            "LeyBot",
            "/foofoo.txt"
        ));
    }

    #[test]
    fn named_empty_eof_group_suppresses_wildcard_fallback() {
        let body = "User-agent: *\nDisallow: /blocked\n\nUser-agent: LeyBot\n";
        assert!(allowed(body, "LeyBot", "/blocked/a"));
        assert!(!allowed(body, "OtherBot", "/blocked/a"));
    }

    #[test]
    fn similar_product_token_does_not_match_by_substring() {
        let body = "User-agent: LeyBotExtra\nDisallow: /private\n";
        assert!(allowed(body, "LeyBot", "/private/a"));
        assert!(!allowed(body, "LeyBotExtra", "/private/a"));
    }

    #[test]
    fn malformed_path_patterns_and_product_tokens_are_ignored() {
        assert!(!allowed(
            "User-agent: LeyBot\nDisallow: /private\nAllow: */private\n",
            "LeyBot",
            "/private"
        ));
        assert!(allowed(
            "User-agent: LeyBot\nDisallow: private\n",
            "LeyBot",
            "/private"
        ));
        assert!(allowed(
            "User-agent: LeyBot\nAllow:\nDisallow:\n",
            "LeyBot",
            "/private"
        ));
        assert!(allowed(
            "User-agent: LeyBot/1.0\nDisallow: /\n",
            "LeyBot/1.0",
            "/private"
        ));
        assert!(!allowed(
            concat!(
                "User-agent: LeyBot\n",
                "Disallow: /one\n",
                "User-agent: LeyBot/1.0\n",
                "Disallow: /two\n",
            ),
            "LeyBot",
            "/two"
        ));

        let exact_groups = concat!(
            "User-agent: LeyBot\n",
            "Disallow: /one\n",
            "User-agent: LeyBot\n",
            "Disallow: /two\n",
        );
        assert!(!allowed(exact_groups, "LeyBot", "/one"));
        assert!(!allowed(exact_groups, "LeyBot", "/two"));
    }

    #[test]
    fn exact_group_replaces_wildcard_fallback() {
        let body = "User-agent: *\nDisallow: /private\n\nUser-agent: LeyBot\nAllow: /private\n";
        assert!(allowed(body, "LeyBot", "/private/a"));
        assert!(!allowed(body, "OtherBot", "/private/a"));
    }

    #[test]
    fn empty_document_and_empty_disallow_allow_requests() {
        assert!(allowed("", "LeyBot", "/anything"));
        assert!(allowed(
            "User-agent: LeyBot\nDisallow:\n",
            "LeyBot",
            "/anything"
        ));
    }

    #[test]
    fn percent_encoded_dollar_is_literal_not_an_end_anchor() {
        let body = "User-agent: LeyBot\nDisallow: /path/foo-%24\n";
        assert!(!allowed(body, "LeyBot", "/path/foo-$"));
        assert!(allowed(body, "LeyBot", "/path/foo-X"));
    }

    #[test]
    fn malformed_lines_do_not_erase_valid_neighbors() {
        let body = concat!(
            "User-agent: LeyBot\n",
            "Disallow: /blocked\n",
            "Disallow /malformed\n",
            "garbage without a colon\n",
            "Allow: /open\n",
            "Sitemap: https://example.invalid/sitemap.xml\n",
            "Disallow: /after\n",
        );
        assert!(!allowed(body, "LeyBot", "/blocked/a"));
        assert!(allowed(body, "LeyBot", "/open/a"));
        assert!(!allowed(body, "LeyBot", "/after/a"));
    }

    #[test]
    fn cr_only_lines_and_malformed_neighbors_keep_rules() {
        let body = b"User-agent: LeyBot\rDisallow /bad\rDisallow: /first\rUser-agent LeyBot\rDisallow: /second\r";
        let parsed = parse_robots(body).unwrap();
        assert!(!allowed_from(&parsed, "LeyBot", "/first/path"));
        assert!(!allowed_from(&parsed, "LeyBot", "/second/path"));
        assert!(allowed_from(&parsed, "LeyBot", "/bad/path"));

        let invalid_utf8 =
            b"User-agent: LeyBot\nDisallow: /before\nDisallow: /bad\xff\nDisallow: /after\n";
        let parsed = parse_robots(invalid_utf8).unwrap();
        assert!(!allowed_from(&parsed, "LeyBot", "/before/path"));
        assert!(allowed_from(&parsed, "LeyBot", "/bad/path"));
        assert!(!allowed_from(&parsed, "LeyBot", "/after/path"));
    }

    #[test]
    fn parses_exact_500_kib_and_applies_rules_after_that_boundary() {
        let boundary = 500 * 1024;
        let mut exact = b"User-agent: LeyBot\n".to_vec();
        exact.resize(boundary, b'#');
        assert_eq!(exact.len(), boundary);
        assert!(allowed_from(
            &parse_robots(&exact).unwrap(),
            "LeyBot",
            "/anything"
        ));

        let mut body = b"User-agent: LeyBot\n".to_vec();
        body.resize(boundary + 1, b'#');
        body.extend_from_slice(b"\nDisallow: /late\n");
        let parsed = parse_robots(&body).expect("input beyond the RFC minimum is supported");
        assert!(!allowed_from(&parsed, "LeyBot", "/late/page"));
    }

    #[test]
    fn rejects_input_above_documented_hard_cap() {
        let body = vec![b' '; MAX_ROBOTS_BYTES + 1];
        let error = parse_robots(&body).expect_err("oversized input must not be truncated");
        assert_eq!(
            error,
            super::ParseError::TooLarge {
                actual: MAX_ROBOTS_BYTES + 1,
                maximum: MAX_ROBOTS_BYTES,
            }
        );
    }
}
