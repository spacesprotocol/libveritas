//! Just enough HTML handling for profile fields: the visible text and the
//! link targets. Platforms return bios as small HTML fragments (Mastodon
//! `note`, Hacker News `about`, X oEmbed), never whole pages.

pub(crate) struct Fragment {
    pub text: String,
    pub links: Vec<String>,
}

pub(crate) fn parse(html: &str) -> Fragment {
    let mut text = String::with_capacity(html.len());
    let mut links = Vec::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        text.push_str(&rest[..lt]);
        let Some(gt) = rest[lt..].find('>') else {
            rest = "";
            break;
        };
        let tag = &rest[lt + 1..lt + gt];
        let name = tag
            .split(|c: char| c.is_whitespace() || c == '/')
            .find(|s| !s.is_empty())
            .unwrap_or_default()
            .to_ascii_lowercase();
        match name.as_str() {
            "br" | "p" | "div" | "li" => text.push('\n'),
            "a" if !tag.starts_with('/') => {
                if let Some(href) = attr(tag, "href") {
                    links.push(decode_entities(href));
                }
            }
            _ => {}
        }
        rest = &rest[lt + gt + 1..];
    }
    text.push_str(rest);
    Fragment {
        text: decode_entities(&text),
        links,
    }
}

/// Inner HTML of the first `<p …>…</p>`.
pub(crate) fn first_paragraph(html: &str) -> Option<&str> {
    let start = html.find("<p")?;
    let open_end = start + html[start..].find('>')? + 1;
    let close = open_end + html[open_end..].find("</p>")?;
    Some(&html[open_end..close])
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name) {
        let at = from + i;
        let after = lower[at + name.len()..].trim_start();
        let boundary = at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace();
        if boundary && after.starts_with('=') {
            let v = tag[tag.len() - after.len() + 1..].trim_start();
            let quote = v.chars().next()?;
            return if quote == '"' || quote == '\'' {
                v[1..].split(quote).next()
            } else {
                v.split(|c: char| c.is_whitespace()).next()
            };
        }
        from = at + name.len();
    }
    None
}

pub(crate) fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let decoded = tail.find(';').filter(|&semi| semi <= 10).and_then(|semi| {
            let ent = &tail[1..semi];
            let c = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                "mdash" => Some('—'),
                "ndash" => Some('–'),
                _ => {
                    let n = if let Some(h) = ent.strip_prefix("#x").or(ent.strip_prefix("#X")) {
                        u32::from_str_radix(h, 16).ok()
                    } else {
                        ent.strip_prefix('#').and_then(|d| d.parse().ok())
                    };
                    n.and_then(char::from_u32)
                }
            };
            c.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_links() {
        let f = parse(
            r#"<p>Builder at <a href="https://nacho.io/alice@bitcoin" rel="me">nacho.io/alice@bitcoin</a><br>I am alice&#64;bitcoin &amp; more</p>"#,
        );
        assert_eq!(f.links, vec!["https://nacho.io/alice@bitcoin"]);
        assert!(f.text.contains("I am alice@bitcoin & more"), "{}", f.text);
    }

    #[test]
    fn hacker_news_about() {
        // HN escapes slashes as &#x2F; and links with <a href>.
        let f = parse("I am alice@bitcoin<p><a href=\"https:&#x2F;&#x2F;nacho.io\">x</a>");
        assert_eq!(f.links, vec!["https://nacho.io"]);
        assert!(f.text.starts_with("I am alice@bitcoin"));
    }

    #[test]
    fn x_oembed_paragraph() {
        let html = r#"<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Verifying myself: I am alice@bitcoin <a href="https://t.co/x">https://t.co/x</a></p>&mdash; Alice (@alice) <a href="https://x.com/alice/status/1">Nov 9</a></blockquote>"#;
        let p = first_paragraph(html).unwrap();
        assert_eq!(
            parse(p).text,
            "Verifying myself: I am alice@bitcoin https://t.co/x"
        );
    }

    #[test]
    fn entities() {
        assert_eq!(
            decode_entities("a &amp; b &#39;c&#39; &bogus; &"),
            "a & b 'c' &bogus; &"
        );
    }
}
