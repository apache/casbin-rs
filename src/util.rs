// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
        let end = string_literal_end(bytes, i);
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

// Returns the index just past the string literal that opens at bytes[i], or
// the end of the input when it is not closed.
fn string_literal_end(bytes: &[u8], i: usize) -> usize {
    let quote = bytes[i];
    let mut end = i + 1;
    while end < bytes.len() && bytes[end] != quote {
        if bytes[end] == b'\\' {
            end += 1;
        }
        end += 1;
    }
    (end + 1).min(bytes.len())
}

// Returns the index of the first comment marker outside string literals.
pub(crate) fn find_comment(s: &str, markers: &[u8]) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i = string_literal_end(bytes, i);
        } else if markers.contains(&bytes[i]) {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

pub fn remove_comment(s: &str) -> String {
    let s = if let Some(idx) = find_comment(s, b"#") {
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
    let mut rest = Some(line);
    while let Some(field) = rest {
        let field = field.trim_start();
        let (value, next) = match parse_quoted_field(field) {
            QuotedField::Value(value, next) => (value, next),
            QuotedField::Unclosed => (field.trim_end().to_owned(), None),
            QuotedField::Not => match field.split_once(',') {
                Some((value, next)) => {
                    (value.trim_end().to_owned(), Some(next))
                }
                None => (field.trim_end().to_owned(), None),
            },
        };
        res.push(value);
        rest = next;
    }
    Some(res)
}

enum QuotedField<'a> {
    Value(String, Option<&'a str>),
    Unclosed,
    Not,
}

// Reads a field quoted the way CSV does, with "" standing for one quote, and
// returns the rest of the line after the comma that ends it. A field that
// does not start with a quote, or has text after its closing quote, is read
// as it is.
fn parse_quoted_field(field: &str) -> QuotedField<'_> {
    let body = match field.strip_prefix('"') {
        Some(body) => body,
        None => return QuotedField::Not,
    };

    let mut value = String::new();
    let mut start = 0;
    loop {
        let end = match body[start..].find('"') {
            Some(i) => start + i,
            None => return QuotedField::Unclosed,
        };
        value.push_str(&body[start..end]);
        if body[end + 1..].starts_with('"') {
            value.push('"');
            start = end + 2;
            continue;
        }

        let after = body[end + 1..].trim_start();
        return if after.is_empty() {
            QuotedField::Value(value, None)
        } else if let Some(next) = after.strip_prefix(',') {
            QuotedField::Value(value, Some(next))
        } else {
            QuotedField::Not
        };
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
    fn test_remove_comment_in_string_literal() {
        assert_eq!(
            r#"r.obj == "data#1" && r.act == 'a#b'"#,
            remove_comment(r#"r.obj == "data#1" && r.act == 'a#b' # note"#)
        );
        assert_eq!(
            r##"r.obj == "a\"#b""##,
            remove_comment(r##"r.obj == "a\"#b" # note"##)
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
    fn test_csv_parse_quoted() {
        assert_eq!(
            parse_csv_line(r#"p, "say ""hi"", bob", " data ", , x"#),
            Some(vec![
                "p".to_owned(),
                r#"say "hi", bob"#.to_owned(),
                " data ".to_owned(),
                "".to_owned(),
                "x".to_owned(),
            ])
        );
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
