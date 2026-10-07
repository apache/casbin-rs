#[cfg(all(feature = "runtime-async-std", feature = "ip"))]
use async_std::net::IpAddr;

#[cfg(all(feature = "runtime-tokio", feature = "ip"))]
use std::net::IpAddr;

#[cfg(feature = "glob")]
use globset::GlobBuilder;
#[cfg(feature = "ip")]
use ip_network::IpNetwork;
use once_cell::sync::Lazy;
use regex::Regex;
use rhai::Dynamic;

static MAT_B: Lazy<Regex> = Lazy::new(|| Regex::new(r":[^/]*").unwrap());
static MAT_P: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{[^/]*\}").unwrap());

use std::{borrow::Cow, collections::HashMap};

/// Represents a custom operator function that can be registered with Casbin.
///
/// Custom functions accept Rhai's `Dynamic` type, which can hold any value:
/// - Strings (as `ImmutableString`)
/// - Integers (i32 or i64)
/// - Booleans
/// - Floats (f32 or f64)
/// - Arrays
/// - Maps
/// - And more...
///
/// This allows for flexible custom functions that can work with different types.
///
/// # Example
///
/// ```rust,ignore
/// use casbin::{CoreApi, OperatorFunction};
/// use rhai::Dynamic;
///
/// // Function that works with integers
/// let int_fn = OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
///     let a_int = a.as_int().unwrap_or(0);
///     let b_int = b.as_int().unwrap_or(0);
///     (a_int > b_int).into()
/// });
///
/// // Function that works with strings
/// let str_fn = OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
///     use casbin::model::function_map::dynamic_to_str;
///     let a_str = dynamic_to_str(&a);
///     let b_str = dynamic_to_str(&b);
///     a_str.contains(b_str.as_ref()).into()
/// });
/// ```
#[derive(Clone, Copy)]
pub enum OperatorFunction {
    Arg0(fn() -> Dynamic),
    Arg1(fn(Dynamic) -> Dynamic),
    Arg2(fn(Dynamic, Dynamic) -> Dynamic),
    Arg3(fn(Dynamic, Dynamic, Dynamic) -> Dynamic),
    Arg4(fn(Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic),
    Arg5(fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic),
    Arg6(fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic),
}

pub struct FunctionMap {
    pub(crate) fm: HashMap<String, OperatorFunction>,
}

impl Default for FunctionMap {
    fn default() -> FunctionMap {
        let mut fm: HashMap<String, OperatorFunction> = HashMap::new();
        fm.insert(
            "keyMatch".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                key_match(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );
        fm.insert(
            "keyGet".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                key_get(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );
        fm.insert(
            "keyMatch2".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                key_match2(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );
        fm.insert(
            "keyGet2".to_owned(),
            OperatorFunction::Arg3(|s1: Dynamic, s2: Dynamic, s3: Dynamic| {
                key_get2(
                    &dynamic_to_str(&s1),
                    &dynamic_to_str(&s2),
                    &dynamic_to_str(&s3),
                )
                .into()
            }),
        );
        fm.insert(
            "keyMatch3".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                key_match3(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );
        fm.insert(
            "keyGet3".to_owned(),
            OperatorFunction::Arg3(|s1: Dynamic, s2: Dynamic, s3: Dynamic| {
                key_get3(
                    &dynamic_to_str(&s1),
                    &dynamic_to_str(&s2),
                    &dynamic_to_str(&s3),
                )
                .into()
            }),
        );
        fm.insert(
            "keyMatch4".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                key_match4(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );
        fm.insert(
            "keyMatch5".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                key_match5(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );
        fm.insert(
            "regexMatch".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                regex_match(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );

        #[cfg(feature = "glob")]
        fm.insert(
            "globMatch".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                glob_match(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );

        #[cfg(feature = "ip")]
        fm.insert(
            "ipMatch".to_owned(),
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                ip_match(&dynamic_to_str(&s1), &dynamic_to_str(&s2)).into()
            }),
        );

        FunctionMap { fm }
    }
}

impl FunctionMap {
    #[inline]
    pub fn add_function(&mut self, fname: &str, f: OperatorFunction) {
        self.fm.insert(fname.to_owned(), f);
    }

    #[inline]
    pub fn get_functions(
        &self,
    ) -> impl Iterator<Item = (&String, &OperatorFunction)> {
        self.fm.iter()
    }
}

/// Helper function to convert Dynamic to string reference
///
/// This is useful for custom functions that need string arguments.
/// The function accepts Rhai's Dynamic type and converts it to a string.
///
/// # Example
///
/// ```rust,ignore
/// use casbin::{CoreApi, OperatorFunction, Enforcer};
/// use casbin::model::function_map::dynamic_to_str;
/// use rhai::Dynamic;
///
/// // Create a custom function that takes Dynamic arguments
/// let custom_fn = OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
///     let str1 = dynamic_to_str(&s1);
///     let str2 = dynamic_to_str(&s2);
///     // Your custom logic here
///     (str1 == str2).into()
/// });
/// ```
pub fn dynamic_to_str(d: &Dynamic) -> Cow<'_, str> {
    if d.is_string() {
        match d.clone().into_immutable_string() {
            Ok(s) => Cow::Owned(s.to_string()),
            Err(_) => Cow::Owned(d.to_string()),
        }
    } else {
        Cow::Owned(d.to_string())
    }
}

/// key_match determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain *  
/// For example, "/foo/bar" matches "/foo/*"
pub fn key_match(key1: &str, key2: &str) -> bool {
    if let Some(i) = key2.find('*') {
        key1.starts_with(&key2[..i])
    } else {
        key1 == key2
    }
}

/// key_get returns the matched part  
/// For example, "/foo/bar/foo" matches "/foo/*"  
/// "bar/foo" will be returned.
pub fn key_get(key1: &str, key2: &str) -> String {
    if let Some(i) = key2.find('*') {
        if key1.len() > i && key1.starts_with(&key2[..i]) {
            return key1[i..].to_string();
        }
    }
    "".to_string()
}

/// key_match2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *  
/// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
pub fn key_match2(key1: &str, key2: &str) -> bool {
    let mut key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    key2 = MAT_B.replace_all(&key2, "[^/]+").to_string().into();

    regex_match(key1, &format!("^{}$", key2))
}

/// key_get2 returns value matched pattern  
/// For example, "/resource1" matches "/:resource"  
/// if the pathVar == "resource", then "resource1" will be returned.
pub fn key_get2(key1: &str, key2: &str, path_var: &str) -> String {
    let key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    let re = Regex::new(r":[^/]+").unwrap();
    let keys: Vec<_> = re.find_iter(&key2).collect();
    let key2 = re.replace_all(&key2, "([^/]+)").to_string();
    let key2 = format!("^{}$", key2);

    if let Ok(re2) = Regex::new(&key2) {
        if let Some(caps) = re2.captures(key1) {
            for (i, key) in keys.iter().enumerate() {
                if path_var == &key.as_str()[1..] {
                    return caps
                        .get(i + 1)
                        .map_or("".to_string(), |m| m.as_str().to_string());
                }
            }
        }
    }
    "".to_string()
}

/// key_match3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *  
/// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
pub fn key_match3(key1: &str, key2: &str) -> bool {
    let mut key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    key2 = MAT_P.replace_all(&key2, "[^/]+").to_string().into();

    regex_match(key1, &format!("^{}$", key2))
}

/// key_get3 returns value matched pattern  
/// For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"  
/// if the pathVar == "project", then "project1" will be returned.
pub fn key_get3(key1: &str, key2: &str, path_var: &str) -> String {
    let key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    let re = Regex::new(r"\{[^/]+?\}").unwrap();
    let keys: Vec<_> = re.find_iter(&key2).collect();
    let key2 = re.replace_all(&key2, "([^/]+?)").to_string();
    let key2 = Regex::new(r"\{")
        .unwrap()
        .replace_all(&key2, "\\{")
        .to_string();
    let key2 = format!("^{}$", key2);

    let re2 = Regex::new(&key2).unwrap();
    if let Some(caps) = re2.captures(key1) {
        for (i, key) in keys.iter().enumerate() {
            if path_var == &key.as_str()[1..key.as_str().len() - 1] {
                return caps
                    .get(i + 1)
                    .map_or("".to_string(), |m| m.as_str().to_string());
            }
        }
    }
    "".to_string()
}

/// KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.  
/// Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:  
///   - "/parent/123/child/123" matches "/parent/{id}/child/{id}"
///   - "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
///
/// But KeyMatch3 will match both.
pub fn key_match4(key1: &str, key2: &str) -> bool {
    let mut key2 = key2.replace("/*", "/.*");
    let mut tokens = Vec::new();

    let re = Regex::new(r"\{[^/]+?\}").unwrap();
    key2 = re
        .replace_all(&key2, |caps: &regex::Captures| {
            tokens.push(caps[0][1..caps[0].len() - 1].to_string());
            "([^/]+)".to_string()
        })
        .to_string();

    let re = match Regex::new(&format!("^{}$", key2)) {
        Ok(re) => re,
        Err(_) => return false,
    };
    if let Some(caps) = re.captures(key1) {
        let matches: Vec<_> =
            caps.iter().skip(1).map(|m| m.unwrap().as_str()).collect();
        if tokens.len() != matches.len() {
            panic!(
                "KeyMatch4: number of tokens is not equal to number of values"
            );
        }

        let mut values = HashMap::new();
        for (token, value) in tokens.iter().zip(matches.iter()) {
            if let Some(existing_value) = values.get(token) {
                if *existing_value != value {
                    return false;
                }
            } else {
                values.insert(token, value);
            }
        }
        true
    } else {
        false
    }
}

/// KeyMatch5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *  
/// For example,  
///   - "/foo/bar?status=1&type=2" matches "/foo/bar"
///   - "/parent/child1" and "/parent/child1" matches "/parent/*"
///   - "/parent/child1?status=1" matches "/parent/*".
pub fn key_match5(key1: &str, key2: &str) -> bool {
    let key1 = if let Some(i) = key1.find('?') {
        &key1[..i]
    } else {
        key1
    };

    let key2 = key2.replace("/*", "/.*");
    let key2 = Regex::new(r"(\{[^/]+?\})")
        .unwrap()
        .replace_all(&key2, "[^/]+");

    regex_match(key1, &format!("^{}$", key2))
}

// regex_match determines whether key1 matches the pattern of key2 in regular expression.
pub fn regex_match(key1: &str, key2: &str) -> bool {
    Regex::new(key2).unwrap().is_match(key1)
}

// ip_match determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
#[cfg(feature = "ip")]
pub fn ip_match(key1: &str, key2: &str) -> bool {
    let key2_split = key2.splitn(2, '/').collect::<Vec<&str>>();
    let ip_addr2 = key2_split[0];

    if let (Ok(ip_addr1), Ok(ip_addr2)) =
        (key1.parse::<IpAddr>(), ip_addr2.parse::<IpAddr>())
    {
        if key2_split.len() == 2 {
            match key2_split[1].parse::<u8>() {
                Ok(ip_netmask) => {
                    match IpNetwork::new_truncate(ip_addr2, ip_netmask) {
                        Ok(ip_network) => ip_network.contains(ip_addr1),
                        Err(err) => panic!("invalid ip network {}", err),
                    }
                }
                _ => panic!("invalid netmask {}", key2_split[1]),
            }
        } else {
            if let (IpAddr::V4(ip_addr1_new), IpAddr::V6(ip_addr2_new)) =
                (ip_addr1, ip_addr2)
            {
                if let Some(ip_addr2_new) = ip_addr2_new.to_ipv4() {
                    return ip_addr2_new == ip_addr1_new;
                }
            }

            ip_addr1 == ip_addr2
        }
    } else {
        panic!("invalid argument {} {}", key1, key2)
    }
}

// glob_match determines whether key1 matches the pattern of key2 using glob pattern
#[cfg(feature = "glob")]
pub fn glob_match(key1: &str, key2: &str) -> bool {
    GlobBuilder::new(key2)
        .literal_separator(true)
        .build()
        .unwrap()
        .compile_matcher()
        .is_match(key1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_match() {
        assert!(key_match("/foo/bar", "/foo/*"));
        assert!(!key_match("/bar/foo", "/foo/*"));
        assert!(key_match("/bar", "/ba*"));
        assert!(!key_match("ééééé", "/foo/*"));
        assert!(key_match("/éé/bar", "/éé/*"));
    }

    #[test]
    fn test_key_get() {
        assert_eq!(key_get("/foo", "/foo"), "");
        assert_eq!(key_get("/foo", "/foo*"), "");
        assert_eq!(key_get("/foo", "/foo/*"), "");
        assert_eq!(key_get("/foo/bar", "/foo"), "");
        assert_eq!(key_get("/foo/bar", "/foo*"), "/bar");
        assert_eq!(key_get("/foo/bar", "/foo/*"), "bar");
        assert_eq!(key_get("/foobar", "/foo"), "");
        assert_eq!(key_get("/foobar", "/foo*"), "bar");
        assert_eq!(key_get("/foobar", "/foo/*"), "");
        assert_eq!(key_get("ééééé", "/foo/*"), "");
        assert_eq!(key_get("/éé/bar", "/éé/*"), "bar");
    }

    #[test]
    fn test_key_match2() {
        assert!(key_match2("/foo/bar", "/foo/*"));
        assert!(key_match2("/foo/bar/baz", "/foo/*"));
        assert!(key_match2("/foo/baz", "/foo/:bar"));
        assert!(key_match2("/foo/baz", "/:foo/:bar"));
        assert!(key_match2("/foo/baz/foo", "/foo/:bar/foo"));
        assert!(!key_match2("/baz", "/foo"));

        // GH Issue #282
        assert!(key_match2("/foo/bar", "/foo/:"));
        assert!(!key_match2("/foo/bar/baz", "/foo/:"));
        assert!(key_match2("/foo/bar/baz", "/foo/:/baz"));
        assert!(!key_match2("/foo/bar", "/foo/:/baz"));
    }

    #[test]
    fn test_key_get2() {
        assert_eq!(key_get2("/foo", "/foo", "id"), "");
        assert_eq!(key_get2("/foo", "/foo*", "id"), "");
        assert_eq!(key_get2("/foo", "/foo/*", "id"), "");
        assert_eq!(key_get2("/foo/bar", "/foo", "id"), "");
        assert_eq!(key_get2("/foo/bar", "/foo*", "id"), "");
        assert_eq!(key_get2("/foo/bar", "/foo/*", "id"), "");
        assert_eq!(key_get2("/foobar", "/foo", "id"), "");
        assert_eq!(key_get2("/foobar", "/foo*", "id"), "");
        assert_eq!(key_get2("/foobar", "/foo/*", "id"), "");

        assert_eq!(key_get2("/", "/:resource", "resource"), "");
        assert_eq!(
            key_get2("/resource1", "/:resource", "resource"),
            "resource1"
        );
        assert_eq!(key_get2("/myid", "/:id/using/:resId", "id"), "");
        assert_eq!(
            key_get2("/myid/using/myresid", "/:id/using/:resId", "id"),
            "myid"
        );
        assert_eq!(
            key_get2("/myid/using/myresid", "/:id/using/:resId", "resId"),
            "myresid"
        );

        assert_eq!(key_get2("/proxy/myid", "/proxy/:id/*", "id"), "");
        assert_eq!(key_get2("/proxy/myid/", "/proxy/:id/*", "id"), "myid");
        assert_eq!(key_get2("/proxy/myid/res", "/proxy/:id/*", "id"), "myid");
        assert_eq!(
            key_get2("/proxy/myid/res/res2", "/proxy/:id/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get2("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get2("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id"),
            "myid"
        );
        assert_eq!(key_get2("/proxy/", "/proxy/:id/*", "id"), "");

        assert_eq!(key_get2("/alice", "/:id", "id"), "alice");
        assert_eq!(key_get2("/alice/all", "/:id/all", "id"), "alice");
        assert_eq!(key_get2("/alice", "/:id/all", "id"), "");
        assert_eq!(key_get2("/alice/all", "/:id", "id"), "");

        assert_eq!(key_get2("/alice/all", "/:/all", ""), "");
    }

    #[test]
    fn test_regex_match() {
        assert!(regex_match("foobar", "^foo*"));
        assert!(!regex_match("barfoo", "^foo*"));
    }

    #[test]
    fn test_key_match3() {
        assert!(key_match3("/foo/bar", "/foo/*"));
        assert!(key_match3("/foo/bar/baz", "/foo/*"));
        assert!(key_match3("/foo/baz", "/foo/{bar}"));
        assert!(key_match3("/foo/baz/foo", "/foo/{bar}/foo"));
        assert!(!key_match3("/baz", "/foo"));

        // GH Issue #282
        assert!(key_match3("/foo/bar", "/foo/{}"));
        assert!(key_match3("/foo/{}", "/foo/{}"));
        assert!(!key_match3("/foo/bar/baz", "/foo/{}"));
        assert!(!key_match3("/foo/bar", "/foo/{}/baz"));
        assert!(key_match3("/foo/bar/baz", "/foo/{}/baz"));
    }

    #[test]
    fn test_key_get3() {
        assert_eq!(key_get3("/foo", "/foo", "id"), "");
        assert_eq!(key_get3("/foo", "/foo*", "id"), "");
        assert_eq!(key_get3("/foo", "/foo/*", "id"), "");
        assert_eq!(key_get3("/foo/bar", "/foo", "id"), "");
        assert_eq!(key_get3("/foo/bar", "/foo*", "id"), "");
        assert_eq!(key_get3("/foo/bar", "/foo/*", "id"), "");
        assert_eq!(key_get3("/foobar", "/foo", "id"), "");
        assert_eq!(key_get3("/foobar", "/foo*", "id"), "");
        assert_eq!(key_get3("/foobar", "/foo/*", "id"), "");

        assert_eq!(key_get3("/", "/{resource}", "resource"), "");
        assert_eq!(
            key_get3("/resource1", "/{resource}", "resource"),
            "resource1"
        );
        assert_eq!(key_get3("/myid", "/{id}/using/{resId}", "id"), "");
        assert_eq!(
            key_get3("/myid/using/myresid", "/{id}/using/{resId}", "id"),
            "myid"
        );
        assert_eq!(
            key_get3("/myid/using/myresid", "/{id}/using/{resId}", "resId"),
            "myresid"
        );

        assert_eq!(key_get3("/proxy/myid", "/proxy/{id}/*", "id"), "");
        assert_eq!(key_get3("/proxy/myid/", "/proxy/{id}/*", "id"), "myid");
        assert_eq!(key_get3("/proxy/myid/res", "/proxy/{id}/*", "id"), "myid");
        assert_eq!(
            key_get3("/proxy/myid/res/res2", "/proxy/{id}/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/res/*", "id"),
            "myid"
        );
        assert_eq!(key_get3("/proxy/", "/proxy/{id}/*", "id"), "");

        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{proj}_admin/info",
                "proj"
            ),
            ""
        );
        assert_eq!(
            key_get3("/{id/using/myresid", "/{id/using/{resId}", "resId"),
            "myresid"
        );
        assert_eq!(
            key_get3(
                "/{id/using/myresid/status}",
                "/{id/using/{resId}/status}",
                "resId"
            ),
            "myresid"
        );

        assert_eq!(
            key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/*/{res}", "res"),
            "res3"
        );
        assert_eq!(
            key_get3(
                "/api/project1_admin/info",
                "/api/{proj}_admin/info",
                "proj"
            ),
            "project1"
        );
        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{g}_{gn}/{proj}_admin/info",
                "g"
            ),
            "group1"
        );
        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{g}_{gn}/{proj}_admin/info",
                "gn"
            ),
            "group_name"
        );
        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{g}_{gn}/{proj}_admin/info",
                "proj"
            ),
            "project1"
        );
    }

    #[test]
    fn test_key_match4() {
        assert!(key_match4(
            "/parent/123/child/123",
            "/parent/{id}/child/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/456",
            "/parent/{id}/child/{id}"
        ));
        assert!(key_match4(
            "/parent/123/child/123",
            "/parent/{id}/child/{another_id}"
        ));
        assert!(key_match4(
            "/parent/123/child/456",
            "/parent/{id}/child/{another_id}"
        ));
        assert!(key_match4(
            "/parent/123/child/123",
            "/parent/{id}/child/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/456",
            "/parent/{id}/child/{id}"
        ));
        assert!(key_match4(
            "/parent/123/child/123",
            "/parent/{id}/child/{another_id}"
        ));
        assert!(key_match4(
            "/parent/123/child/123/book/123",
            "/parent/{id}/child/{id}/book/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/123/book/456",
            "/parent/{id}/child/{id}/book/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/456/book/123",
            "/parent/{id}/child/{id}/book/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/456/book/",
            "/parent/{id}/child/{id}/book/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/456",
            "/parent/{id}/child/{id}/book/{id}"
        ));
        assert!(!key_match4(
            "/parent/123/child/123",
            "/parent/{i/d}/child/{i/d}"
        ));
    }

    #[test]
    fn test_key_match5() {
        assert!(key_match5("/foo/bar?status=1&type=2", "/foo/bar"));
        assert!(key_match5("/parent/child1", "/parent/*"));
        assert!(key_match5("/parent/child1?status=1", "/parent/*"));
        assert!(key_match5("/parent/child1?status=1", "/parent/child1"));
    }

    #[cfg(feature = "ip")]
    #[test]
    fn test_ip_match() {
        assert!(ip_match("::1", "::0:1"));
        assert!(ip_match("192.168.1.1", "192.168.1.1"));
        assert!(ip_match("127.0.0.1", "::ffff:127.0.0.1"));
        assert!(ip_match("192.168.2.123", "192.168.2.0/24"));
        assert!(!ip_match("::1", "127.0.0.2"));
        assert!(!ip_match("192.168.2.189", "192.168.1.134/26"));
    }

    #[cfg(feature = "ip")]
    #[test]
    #[should_panic]
    fn test_ip_match_panic_1() {
        assert!(ip_match("I am alice", "127.0.0.1"));
    }

    #[cfg(feature = "ip")]
    #[test]
    #[should_panic]
    fn test_ip_match_panic_2() {
        assert!(ip_match("127.0.0.1", "I am alice"));
    }

    #[cfg(feature = "glob")]
    #[test]
    fn test_glob_match() {
        assert!(glob_match("/abc/123", "/abc/*"));
        assert!(!glob_match("/abc/123/456", "/abc/*"));
        assert!(glob_match("/abc/123/456", "/abc/**"));
    }
}
