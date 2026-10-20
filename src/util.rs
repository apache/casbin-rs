use once_cell::sync::Lazy;
use regex::Regex;

use std::borrow::Cow;

macro_rules! regex {
    ($re:expr) => {
        ::regex::Regex::new($re).unwrap()
    };
}

static ESC_A: Lazy<Regex> = Lazy::new(|| regex!(r"\b(r\d*|p\d*)\."));
#[allow(dead_code)]
static ESC_G: Lazy<Regex> = Lazy::new(|| {
    regex!(r"\b(g\d*)\(((?:\s*[r|p]\d*\.\w+\s*,\s*){1,2}\s*[r|p]\d*\.\w+\s*)\)")
});
static ESC_C: Lazy<Regex> = Lazy::new(|| regex!(r#"(\s*"[^"]*"?|\s*[^,]*)"#));
static ESC_IN: Lazy<Regex> = Lazy::new(|| regex!(r"\bin\s*\(([^()]*)\)"));
pub(crate) static ESC_E: Lazy<Regex> =
    Lazy::new(|| regex!(r"\beval\(([^)]*)\)"));

pub fn escape_assertion(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut res = String::with_capacity(s.len());
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }
        let mut end = i + 1;
        while end < bytes.len() && bytes[end] != quote {
            if bytes[end] == b'\\' {
                end += 1;
            }
            end += 1;
        }
        let end = (end + 1).min(bytes.len());
        res.push_str(&ESC_A.replace_all(&s[start..i], "${1}_"));
        if quote == b'\'' && end - i >= 2 && bytes[end - 1] == quote {
            res.push('"');
            let mut escaped = false;
            for c in s[i + 1..end - 1].chars() {
                if c == '"' && !escaped {
                    res.push('\\');
                }
                escaped = c == '\\' && !escaped;
                res.push(c);
            }
            res.push('"');
        } else {
            res.push_str(&s[i..end]);
        }
        start = end;
        i = end;
    }
    res.push_str(&ESC_A.replace_all(&s[start..], "${1}_"));
    res
}

pub fn escape_in_operator(m: &str) -> Cow<'_, str> {
    ESC_IN.replace_all(m, "in [${1}]")
}

pub fn remove_comment(s: &str) -> String {
    let s = if let Some(idx) = s.find('#') {
        &s[..idx]
    } else {
        s
    };

    s.trim_end().to_owned()
}

pub fn escape_eval(m: &str) -> Cow<'_, str> {
    ESC_E.replace_all(m, "eval(escape_assertion(${1}))")
}

pub fn parse_csv_line<'a, S: AsRef<str> + 'a>(line: S) -> Option<Vec<String>> {
    let line = line.as_ref().trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut res = vec![];
    for col in ESC_C.find_iter(line).map(|m| m.as_str().trim()) {
        res.push({
            if col.len() >= 2 && col.starts_with('"') && col.ends_with('"') {
                col[1..col.len() - 1].to_owned()
            } else {
                col.to_owned()
            }
        })
    }
    if res.is_empty() {
        None
    } else {
        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_comment() {
        assert!(remove_comment("#").is_empty());
        assert_eq!(
            r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root""#,
            remove_comment(
                r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root" # root is the super user"#
            )
        );
    }

    #[test]
    fn test_escape_assertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act";

        assert_eq!(exp, escape_assertion(s));

        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act";
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act";

        assert_eq!(exp1, escape_assertion(s1));

        assert_eq!(
            r#"r_sub == p_sub && r_obj == "https://p.example.com""#,
            escape_assertion(
                r#"r.sub == p.sub && r.obj == "https://p.example.com""#
            )
        );
        assert_eq!(
            r#"r_obj == "a\"p.b" || p_obj == "r""#,
            escape_assertion(r#"r.obj == "a\"p.b" || p.obj == 'r'"#)
        );
    }

    #[test]
    fn test_csv_parse_1() {
        assert_eq!(
            parse_csv_line("alice, domain1, data1, action1"),
            Some(vec![
                "alice".to_owned(),
                "domain1".to_owned(),
                "data1".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_2() {
        assert_eq!(
            parse_csv_line("alice, \"domain1, domain2\", data1 , action1"),
            Some(vec![
                "alice".to_owned(),
                "domain1, domain2".to_owned(),
                "data1".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_3() {
        assert_eq!(
            parse_csv_line(","),
            Some(vec!["".to_owned(), "".to_owned(),])
        )
    }

    #[test]
    fn test_csv_parse_4() {
        assert_eq!(parse_csv_line(" "), None);
        assert_eq!(parse_csv_line("#"), None);
        assert_eq!(parse_csv_line(" #"), None);
    }

    #[test]
    fn test_csv_parse_5() {
        assert_eq!(
            parse_csv_line(
                "alice, \"domain1, domain2\", \"data1, data2\", action1"
            ),
            Some(vec![
                "alice".to_owned(),
                "domain1, domain2".to_owned(),
                "data1, data2".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_6() {
        assert_eq!(parse_csv_line("\" "), Some(vec!["\"".to_owned()]))
    }

    #[test]
    fn test_csv_parse_7() {
        assert_eq!(
            parse_csv_line("\" alice"),
            Some(vec!["\" alice".to_owned()])
        )
    }

    #[test]
    fn test_csv_parse_8() {
        assert_eq!(
            parse_csv_line("alice, \"domain1, domain2"),
            Some(vec!["alice".to_owned(), "\"domain1, domain2".to_owned(),])
        )
    }

    #[test]
    fn test_csv_parse_9() {
        assert_eq!(parse_csv_line("\"\""), Some(vec!["".to_owned()]));
    }

    #[test]
    fn test_csv_parse_10() {
        assert_eq!(
            parse_csv_line("r.sub.Status == \"ACTIVE\", /data1, read"),
            Some(vec![
                "r.sub.Status == \"ACTIVE\"".to_owned(),
                "/data1".to_owned(),
                "read".to_owned()
            ])
        );
    }
}
