use crate::{CoreApi, Enforcer};
use std::collections::HashMap;

pub fn casbin_js_get_permission_for_user(
    e: &Enforcer,
    _user: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let model = e.get_model();
    let mut m = HashMap::new();

    m.insert("m", serde_json::Value::from(model.to_text()));

    let mut p_rules = Vec::new();
    if let Some(assertions) = model.get_model().get("p") {
        for (ptype, _assertion) in assertions {
            let policies = model.get_policy("p", ptype);
            for rules in policies {
                let mut rule = vec![ptype.to_string()];
                rule.extend(rules);
                p_rules.push(rule);
            }
        }
    }
    m.insert("p", serde_json::Value::from(p_rules));

    let mut g_rules = Vec::new();
    if let Some(assertions) = model.get_model().get("g") {
        for (ptype, _assertion) in assertions {
            let policies = model.get_policy("g", ptype);
            for rules in policies {
                let mut rule = vec![ptype.to_string()];
                rule.extend(rules);
                g_rules.push(rule);
            }
        }
    }
    m.insert("g", serde_json::Value::from(g_rules));

    let result = serde_json::to_string(&m)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::frontend::casbin_js_get_permission_for_user;
    use crate::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_casbin_js_get_permission_for_user() {
        use serde_json::Value;
        use std::fs;
        use std::io::Read;

        let model_path = "examples/rbac_model.conf";
        let policy_path = "examples/rbac_with_hierarchy_policy.csv";
        let e = Enforcer::new(model_path, policy_path).await.unwrap();

        let received_string =
            casbin_js_get_permission_for_user(&e, "alice").unwrap();
        let received: Value = serde_json::from_str(&received_string).unwrap();

        let mut expected_model = String::new();
        fs::File::open(model_path)
            .unwrap()
            .read_to_string(&mut expected_model)
            .unwrap();
        let expected_model_str = expected_model
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("\n\n", "\n");

        assert_eq!(
            received["m"].as_str().unwrap().trim(),
            expected_model_str.trim()
        );

        let mut expected_policies = String::new();
        fs::File::open(policy_path)
            .unwrap()
            .read_to_string(&mut expected_policies)
            .unwrap();
        let expected_policies_items: Vec<&str> =
            expected_policies.split(&[',', '\n'][..]).collect();

        let mut i = 0;
        for s_arr in received["p"].as_array().unwrap() {
            for s in s_arr.as_array().unwrap() {
                assert_eq!(
                    s.as_str().unwrap().trim(),
                    expected_policies_items[i].trim()
                );
                i += 1;
            }
        }
    }
}
