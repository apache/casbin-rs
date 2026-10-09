use crate::{
    config::Config,
    error::ModelError,
    model::{Assertion, AssertionMap, Model},
    rbac::RoleManager,
    util::*,
    Result,
};

#[cfg(feature = "incremental")]
use crate::emitter::EventData;

use hashlink::{LinkedHashMap, LinkedHashSet};
use parking_lot::RwLock;

#[cfg(all(feature = "runtime-async-std", not(target_arch = "wasm32")))]
use async_std::path::Path as ioPath;

#[cfg(feature = "runtime-tokio")]
use std::path::Path as ioPath;

use rhai::{Engine, AST};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Default)]
pub struct DefaultModel {
    pub(crate) model: HashMap<String, AssertionMap>,
    // Precompiled matcher expressions - compiled during Model initialization
    // Keys are full matcher names (e.g., "m", "m2", "m3")
    compiled_matchers: HashMap<String, AST>,
}

impl DefaultModel {
    // Compiles all matcher expressions after Model loading is complete
    // Should be called before Enforcer is used
    pub fn compile_matchers(&mut self, engine: &Engine) -> Result<()> {
        self.compiled_matchers.clear();

        // Only compile matchers from the 'm' section
        if let Some(assertions) = self.model.get("m") {
            for (key, assertion) in assertions {
                let compiled = engine
                    .compile_expression(crate::util::escape_eval(
                        &assertion.value,
                    ))
                    .map_err(|e| {
                        crate::error::Error::ModelError(
                            crate::error::ModelError::M(format!(
                                "Failed to compile matcher '{}': {}",
                                key, e
                            )),
                        )
                    })?;

                // Directly use the complete matcher key as HashMap key
                self.compiled_matchers.insert(key.clone(), compiled);
            }
        }
        Ok(())
    }

    // Gets the precompiled matcher - O(1) lookup, simple and direct
    #[inline]
    pub fn get_compiled_matcher(&self, key: &str) -> Option<&AST> {
        self.compiled_matchers.get(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn from_file<P: AsRef<ioPath>>(p: P) -> Result<DefaultModel> {
        let cfg = Config::from_file(p).await?;

        let mut model = DefaultModel::default();

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    #[allow(clippy::should_implement_trait)]
    pub async fn from_str(s: &str) -> Result<DefaultModel> {
        let cfg = Config::from_str(s).await?;

        let mut model = DefaultModel::default();

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    fn load_section(&mut self, cfg: &Config, sec: &str) -> Result<()> {
        let mut i = 1;

        loop {
            if !self.load_assertion(
                cfg,
                sec,
                &format!("{}{}", sec, self.get_key_suffix(i)),
            )? {
                break Ok(());
            } else {
                i += 1;
            }
        }
    }

    fn load_assertion(
        &mut self,
        cfg: &Config,
        sec: &str,
        key: &str,
    ) -> Result<bool> {
        let sec_name = match sec {
            "r" => "request_definition",
            "p" => "policy_definition",
            "g" => "role_definition",
            "e" => "policy_effect",
            "m" => "matchers",
            _ => {
                return Err(ModelError::Other(format!(
                    "Unknown section: `{}`",
                    sec
                ))
                .into());
            }
        };

        if let Some(val) = cfg.get_str(&format!("{}::{}", sec_name, key)) {
            Ok(self.add_def(sec, key, val))
        } else {
            Ok(false)
        }
    }

    fn get_key_suffix(&self, i: u64) -> String {
        if i == 1 {
            "".to_owned()
        } else {
            i.to_string()
        }
    }
}

impl Model for DefaultModel {
    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool {
        let mut ast = Assertion {
            key: key.to_owned(),
            value: remove_comment(value),
            ..Default::default()
        };

        if ast.value.is_empty() {
            return false;
        }

        if sec == "r" || sec == "p" {
            ast.tokens = ast
                .value
                .split(',')
                .map(|x| format!("{}_{}", key, x.trim()))
                .collect();
        } else {
            ast.value = escape_assertion(&ast.value);
        }

        if let Some(new_model) = self.model.get_mut(sec) {
            new_model.insert(key.to_owned(), ast);
        } else {
            let mut new_ast_map = LinkedHashMap::new();
            new_ast_map.insert(key.to_owned(), ast);
            self.model.insert(sec.to_owned(), new_ast_map);
        }

        true
    }

    #[inline]
    fn get_model(&self) -> &HashMap<String, AssertionMap> {
        &self.model
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut HashMap<String, AssertionMap> {
        &mut self.model
    }

    fn build_role_links(
        &mut self,
        rm_map: &HashMap<String, Arc<RwLock<dyn RoleManager>>>,
    ) -> Result<()> {
        if let Some(asts) = self.model.get_mut("g") {
            for (ptype, ast) in asts.iter_mut() {
                if let Some(rm) = rm_map.get(ptype) {
                    ast.build_role_links(Arc::clone(rm))?;
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "incremental")]
    fn build_incremental_role_links(
        &mut self,
        rm_map: &HashMap<String, Arc<RwLock<dyn RoleManager>>>,
        d: EventData,
    ) -> Result<()> {
        let (ast, rm) = match d {
            EventData::AddPolicy(ref sec, ref ptype, _)
            | EventData::AddPolicies(ref sec, ref ptype, _)
            | EventData::RemovePolicy(ref sec, ref ptype, _)
            | EventData::RemovePolicies(ref sec, ref ptype, _)
            | EventData::RemoveFilteredPolicy(ref sec, ref ptype, _)
                if sec == "g" =>
            {
                (
                    self.model
                        .get_mut(sec)
                        .and_then(|ast_map| ast_map.get_mut(ptype)),
                    rm_map.get(ptype),
                )
            }
            _ => (None, None),
        };

        if let (Some(ast), Some(rm)) = (ast, rm) {
            ast.build_incremental_role_links(Arc::clone(rm), d)?;
        }

        Ok(())
    }

    fn add_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> bool {
        if let Some(ast_map) = self.model.get_mut(sec) {
            if let Some(ast) = ast_map.get_mut(ptype) {
                return ast.policy.insert(rule);
            }
        }
        false
    }

    fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> bool {
        let mut all_added = true;
        if let Some(ast_map) = self.model.get_mut(sec) {
            if let Some(ast) = ast_map.get_mut(ptype) {
                for rule in &rules {
                    if ast.policy.contains(rule) {
                        all_added = false;
                        return all_added;
                    }
                }
                ast.policy.extend(rules);
            }
        }
        all_added
    }

    fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>> {
        if let Some(t1) = self.model.get(sec) {
            if let Some(t2) = t1.get(ptype) {
                return t2.policy.iter().map(|x| x.to_owned()).collect();
            }
        }
        vec![]
    }

    fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        let mut res = vec![];
        if let Some(t1) = self.model.get(sec) {
            if let Some(t2) = t1.get(ptype) {
                for rule in t2.policy.iter() {
                    let mut matched = true;
                    for (i, field_value) in field_values.iter().enumerate() {
                        if !field_value.is_empty()
                            && &rule[field_index + i] != field_value
                        {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res.push(rule.iter().map(String::from).collect());
                    }
                }
            }
        }
        res
    }

    fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        let policy = self.get_policy(sec, ptype);
        for r in policy {
            if r == rule {
                return true;
            }
        }
        false
    }

    fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String> {
        self.get_policy(sec, ptype)
            .into_iter()
            .fold(LinkedHashSet::new(), |mut acc, x| {
                acc.insert(x[field_index].clone());
                acc
            })
            .into_iter()
            .collect()
    }

    fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> bool {
        if let Some(ast_map) = self.model.get_mut(sec) {
            if let Some(ast) = ast_map.get_mut(ptype) {
                return ast.policy.remove(&rule);
            }
        }
        false
    }

    fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> bool {
        let mut all_removed = true;
        if let Some(ast_map) = self.model.get_mut(sec) {
            if let Some(ast) = ast_map.get_mut(ptype) {
                for rule in &rules {
                    if !ast.policy.contains(rule) {
                        all_removed = false;
                        return all_removed;
                    }
                }
                for rule in &rules {
                    ast.policy.remove(rule);
                }
            }
        }
        all_removed
    }

    fn clear_policy(&mut self) {
        if let Some(model_p) = self.model.get_mut("p") {
            for ast in model_p.values_mut() {
                ast.policy.clear();
            }
        }

        if let Some(model_g) = self.model.get_mut("g") {
            for ast in model_g.values_mut() {
                ast.policy.clear();
            }
        }
    }

    fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> (bool, Vec<Vec<String>>) {
        if field_values.is_empty() {
            return (false, vec![]);
        }

        let mut res = false;
        let mut rules_removed: Vec<Vec<String>> = vec![];
        if let Some(ast_map) = self.model.get_mut(sec) {
            if let Some(ast) = ast_map.get_mut(ptype) {
                for rule in ast.policy.iter() {
                    let mut matched = true;
                    for (i, field_value) in field_values.iter().enumerate() {
                        if !field_value.is_empty()
                            && &rule[field_index + i] != field_value
                        {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res = true;
                        rules_removed.push(rule.clone());
                    }
                }
                if res && !rules_removed.is_empty() {
                    for rule in rules_removed.iter() {
                        ast.policy.remove(rule);
                    }
                }
            }
        }
        (res, rules_removed)
    }

    fn to_text(&self) -> String {
        let mut token_patterns = HashMap::new();
        let p_pattern = regex::Regex::new(r"^p_").unwrap();
        let r_pattern = regex::Regex::new(r"^r_").unwrap();

        for ptype in ["r", "p"] {
            if let Some(assertion) = self.model.get(ptype) {
                for token in &assertion[ptype].tokens {
                    let new_token = p_pattern.replace_all(token, "p.");
                    let new_token = r_pattern.replace_all(&new_token, "r.");
                    token_patterns.insert(token.clone(), new_token.to_string());
                }
            }
        }

        if let Some(assertions) = self.model.get("e") {
            if let Some(assertion) = assertions.get("e") {
                if assertion.value.contains("p_eft") {
                    token_patterns
                        .insert("p_eft".to_string(), "p.eft".to_string());
                }
            }
        }

        let mut s = String::new();

        let write_string = |sec: &str, s: &mut String| {
            if let Some(assertions) = self.model.get(sec) {
                for (_ptype, assertion) in assertions {
                    let mut value = assertion.value.clone();
                    for (token_pattern, new_token) in &token_patterns {
                        value = value.replace(token_pattern, new_token);
                    }
                    s.push_str(&format!("{} = {}\n", sec, value));
                }
            }
        };

        s.push_str("[request_definition]\n");
        write_string("r", &mut s);
        s.push_str("[policy_definition]\n");
        write_string("p", &mut s);

        if self.model.contains_key("g") {
            s.push_str("[role_definition]\n");
            if let Some(assertions) = self.model.get("g") {
                for (ptype, assertion) in assertions {
                    s.push_str(&format!("{} = {}\n", ptype, assertion.value));
                }
            }
        }

        s.push_str("[policy_effect]\n");
        write_string("e", &mut s);
        s.push_str("[matchers]\n");
        write_string("m", &mut s);

        s
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
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
    async fn test_basic_model() {
        let m = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(("alice", "data1", "read")).unwrap());
        assert!(!e.enforce(("alice", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "data1", "read")).unwrap());
        assert!(!e.enforce(("bob", "data1", "write")).unwrap());
        assert!(!e.enforce(("bob", "data2", "read")).unwrap());
        assert!(e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_basic_model_no_policy() {
        let m = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(!e.enforce(("alice", "data1", "read")).unwrap());
        assert!(!e.enforce(("alice", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "data1", "read")).unwrap());
        assert!(!e.enforce(("bob", "data1", "write")).unwrap());
        assert!(!e.enforce(("bob", "data2", "read")).unwrap());
        assert!(!e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_basic_model_with_root() {
        let m = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(("alice", "data1", "read")).unwrap());
        assert!(e.enforce(("bob", "data2", "write")).unwrap());
        assert!(e.enforce(("root", "data1", "read")).unwrap());
        assert!(e.enforce(("root", "data1", "write")).unwrap());
        assert!(e.enforce(("root", "data2", "read")).unwrap());
        assert!(e.enforce(("root", "data2", "write")).unwrap());
        assert!(!e.enforce(("alice", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "data1", "read")).unwrap());
        assert!(!e.enforce(("bob", "data1", "write")).unwrap());
        assert!(!e.enforce(("bob", "data2", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_basic_model_with_root_no_policy() {
        let m = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(!e.enforce(("alice", "data1", "read")).unwrap());
        assert!(!e.enforce(("bob", "data2", "write")).unwrap());
        assert!(e.enforce(("root", "data1", "read")).unwrap());
        assert!(e.enforce(("root", "data1", "write")).unwrap());
        assert!(e.enforce(("root", "data2", "read")).unwrap());
        assert!(e.enforce(("root", "data2", "write")).unwrap());
        assert!(!e.enforce(("alice", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "data1", "read")).unwrap());
        assert!(!e.enforce(("bob", "data1", "write")).unwrap());
        assert!(!e.enforce(("bob", "data2", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_basic_model_without_users() {
        let m =
            DefaultModel::from_file("examples/basic_without_users_model.conf")
                .await
                .unwrap();

        let adapter =
            FileAdapter::new("examples/basic_without_users_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(("data1", "read")).unwrap());
        assert!(!e.enforce(("data1", "write")).unwrap());
        assert!(!e.enforce(("data2", "read")).unwrap());
        assert!(e.enforce(("data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_basic_model_without_resources() {
        let m = DefaultModel::from_file(
            "examples/basic_without_resources_model.conf",
        )
        .await
        .unwrap();

        let adapter =
            FileAdapter::new("examples/basic_without_resources_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(("alice", "read")).unwrap());
        assert!(e.enforce(("bob", "write")).unwrap());
        assert!(!e.enforce(("alice", "write")).unwrap());
        assert!(!e.enforce(("bob", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_resource_roles() {
        let m = DefaultModel::from_file(
            "examples/rbac_with_resource_roles_model.conf",
        )
        .await
        .unwrap();

        let adapter =
            FileAdapter::new("examples/rbac_with_resource_roles_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_domains() {
        let m =
            DefaultModel::from_file("examples/rbac_with_domains_model.conf")
                .await
                .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            true,
            e.enforce(("alice", "domain1", "data1", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", "domain1", "data1", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "write")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "write")).unwrap()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_domains_runtime() {
        let m =
            DefaultModel::from_file("examples/rbac_with_domains_model.conf")
                .await
                .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_policy(
            vec!["admin", "domain1", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["admin", "domain1", "data1", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["admin", "domain2", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["admin", "domain2", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        e.add_grouping_policy(
            vec!["alice", "admin", "domain1"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["bob", "admin", "domain2"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            true,
            e.enforce(("alice", "domain1", "data1", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", "domain1", "data1", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "write")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "write")).unwrap()
        );

        assert_eq!(
            true,
            e.remove_filtered_policy(
                1,
                vec!["domain1", "data1"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
            .await
            .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data1", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "write")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "write")).unwrap()
        );

        assert_eq!(
            true,
            e.remove_policy(
                vec!["admin", "domain2", "data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
            .await
            .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data1", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data2", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data1", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data2", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "write")).unwrap()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_domains_at_runtime_mock_adapter() {
        let m =
            DefaultModel::from_file("examples/rbac_with_domains_model.conf")
                .await
                .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        e.add_policy(
            vec!["admin", "domain3", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["alice", "admin", "domain3"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            true,
            e.enforce(("alice", "domain3", "data1", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", "domain1", "data1", "read")).unwrap()
        );

        e.remove_filtered_policy(
            1,
            vec!["domain1", "data1"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(
            false,
            e.enforce(("alice", "domain1", "data1", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "domain2", "data2", "read")).unwrap()
        );

        e.remove_policy(
            vec!["admin", "domain2", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(
            false,
            e.enforce(("bob", "domain2", "data2", "read")).unwrap()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_deny() {
        let m = DefaultModel::from_file("examples/rbac_with_deny_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_not_deny() {
        let m =
            DefaultModel::from_file("examples/rbac_with_not_deny_model.conf")
                .await
                .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(false, e.enforce(("alice", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_with_custom_data() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        e.add_grouping_policy(
            vec!["bob", "data2_admin", "custom_data"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());

        e.remove_grouping_policy(
            vec!["bob", "data2_admin", "custom_data"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_using_in_op() {
        let m = DefaultModel::from_file(
            "examples/rbac_model_matcher_using_in_op.conf",
        )
        .await
        .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("guest", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data3", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data3", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_abac() {
        use serde::Serialize;

        let m = DefaultModel::from_file("examples/abac_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let e = Enforcer::new(m, adapter).await.unwrap();

        #[derive(Serialize, Hash)]
        pub struct Book<'a> {
            owner: &'a str,
        }

        assert_eq!(
            false,
            e.enforce(("alice", Book { owner: "bob" }, "read")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", Book { owner: "alice" }, "read"))
                .unwrap()
        );
    }
}
