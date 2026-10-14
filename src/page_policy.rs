#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PageRestrictions {
    pub noindex: bool,
    pub nofollow: bool,
}

impl PageRestrictions {
    fn add_bare(&mut self, item: &str) {
        match classify_directive(item.trim()) {
            Some(HeaderDirective::Noindex) => self.noindex = true,
            Some(HeaderDirective::Nofollow) => self.nofollow = true,
            Some(HeaderDirective::None) => {
                self.noindex = true;
                self.nofollow = true;
            }
            Some(HeaderDirective::Valued | HeaderDirective::Reserved) | None => {}
        }
    }

    pub fn combine(&mut self, other: Self) {
        self.noindex |= other.noindex;
        self.nofollow |= other.nofollow;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderDirective {
    Noindex,
    Nofollow,
    None,
    Valued,
    Reserved,
}

const HEADER_DIRECTIVES: &[(&str, HeaderDirective)] = &[
    ("all", HeaderDirective::Reserved),
    ("indexifembedded", HeaderDirective::Reserved),
    ("max-image-preview", HeaderDirective::Valued),
    ("max-snippet", HeaderDirective::Valued),
    ("max-video-preview", HeaderDirective::Valued),
    ("noarchive", HeaderDirective::Reserved),
    ("nocache", HeaderDirective::Reserved),
    ("noimageindex", HeaderDirective::Reserved),
    ("noindex", HeaderDirective::Noindex),
    ("nofollow", HeaderDirective::Nofollow),
    ("none", HeaderDirective::None),
    ("nositelinkssearchbox", HeaderDirective::Reserved),
    ("nosnippet", HeaderDirective::Reserved),
    ("notranslate", HeaderDirective::Reserved),
    ("unavailable_after", HeaderDirective::Valued),
];

fn classify_directive(name: &str) -> Option<HeaderDirective> {
    HEADER_DIRECTIVES
        .iter()
        .find_map(|(known, kind)| name.eq_ignore_ascii_case(known).then_some(*kind))
}

pub fn parse_x_robots_tags<'a>(fields: impl IntoIterator<Item = &'a str>) -> PageRestrictions {
    let mut combined = PageRestrictions::default();
    for field in fields {
        combined.combine(parse_header_field(field));
    }
    combined
}

fn parse_header_field(field: &str) -> PageRestrictions {
    let items: Vec<&str> = field.split(',').map(str::trim).collect();
    let mut result = PageRestrictions::default();
    let Some(first) = items.first() else {
        return result;
    };

    let first_colon = first.find(':');
    let start_at;
    if let Some(colon) = first_colon {
        let name = first[..colon].trim();
        let value = first[colon + 1..].trim();
        if classify_directive(name).is_some() {
            start_at = 1;
        } else if is_agent_token(name) && !value.is_empty() {
            if !name.eq_ignore_ascii_case("leybot") {
                return result;
            }
            result.add_bare(value);
            start_at = 1;
        } else {
            result.add_bare(value);
            start_at = 1;
        }
    } else {
        result.add_bare(first);
        start_at = 1;
    }

    for item in items.iter().skip(start_at) {
        if item.is_empty() {
            continue;
        }
        if item.contains(':') {
            continue;
        }
        result.add_bare(item);
    }
    result
}

fn is_agent_token(token: &str) -> bool {
    let mut bytes = token.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub fn parse_meta_restrictions(name: &str, content: &str) -> PageRestrictions {
    if !name.eq_ignore_ascii_case("robots") && !name.eq_ignore_ascii_case("leybot") {
        return PageRestrictions::default();
    }
    let mut result = PageRestrictions::default();
    for item in content.split(',') {
        if !item.contains(':') {
            result.add_bare(item);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_repeated_fields_and_meta_restrictions() {
        assert_eq!(
            parse_x_robots_tags(["OtherBot: noindex, nofollow", "LeyBot: nofollow", "noindex"]),
            PageRestrictions {
                noindex: true,
                nofollow: true
            }
        );
        assert_eq!(
            parse_meta_restrictions("LeYbOt", "index, NONE"),
            PageRestrictions {
                noindex: true,
                nofollow: true
            }
        );
        assert_eq!(
            parse_meta_restrictions("OtherBot", "noindex"),
            PageRestrictions::default()
        );
    }

    #[test]
    fn malformed_and_valued_items_do_not_discard_neighbors() {
        assert_eq!(
            parse_x_robots_tags([
                "bad token: noindex, nofollow",
                "noarchive: malformed, noindex",
                "max-snippet: 50, none",
                "LeyBot: noindex, OtherBot: nofollow, nofollow",
                "OtherBot: noindex, nofollow",
            ]),
            PageRestrictions {
                noindex: true,
                nofollow: true
            }
        );
        assert_eq!(
            parse_x_robots_tags(["OtherBot: noindex, nofollow"]),
            PageRestrictions::default()
        );
        assert_eq!(
            parse_x_robots_tags(["max-snippet: noindex"]),
            PageRestrictions::default()
        );
        assert_eq!(
            parse_x_robots_tags(["noindex, max-snippet: 50, nofollow"]),
            PageRestrictions {
                noindex: true,
                nofollow: true
            }
        );
    }
}
