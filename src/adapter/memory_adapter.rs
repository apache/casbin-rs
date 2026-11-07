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

use crate::{
    adapter::{Adapter, Filter},
    model::Model,
    Result,
};

use async_trait::async_trait;
use hashlink::LinkedHashSet;

#[derive(Default)]
pub struct MemoryAdapter {
    policy: LinkedHashSet<Vec<String>>,
    is_filtered: bool,
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.is_filtered = false;
        for line in self.policy.iter() {
            let sec = &line[0];
            let ptype = &line[1];
            let rule = line[2..].to_vec().clone();

            if let Some(t1) = m.get_mut_model().get_mut(sec) {
                if let Some(t2) = t1.get_mut(ptype) {
                    t2.get_mut_policy().insert(rule);
                }
            }
        }

        Ok(())
    }

    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<()> {
        for line in self.policy.iter() {
            let sec = &line[0];
            let ptype = &line[1];
            let rule = line[1..].to_vec().clone();
            let mut is_filtered = false;

            if sec == "p" {
                for (i, r) in f.p.iter().enumerate() {
                    if !r.is_empty() && r != &rule[i + 1] {
                        is_filtered = true;
                    }
                }
            }
            if sec == "g" {
                for (i, r) in f.g.iter().enumerate() {
                    if !r.is_empty() && r != &rule[i + 1] {
                        is_filtered = true;
                    }
                }
            }

            if !is_filtered {
                if let Some(ast_map) = m.get_mut_model().get_mut(sec) {
                    if let Some(ast) = ast_map.get_mut(ptype) {
                        ast.get_mut_policy().insert(rule);
                    }
                }
            } else {
                self.is_filtered = true;
            }
        }
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.policy.clear();

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                if let Some(sec) = ptype.chars().next().map(|x| x.to_string()) {
                    for policy in ast.get_policy() {
                        let mut rule = policy.clone();
                        rule.insert(0, ptype.clone());
                        rule.insert(0, sec.clone());
                        self.policy.insert(rule);
                    }
                }
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                if let Some(sec) = ptype.chars().next().map(|x| x.to_string()) {
                    for policy in ast.get_policy() {
                        let mut rule = policy.clone();
                        rule.insert(0, ptype.clone());
                        rule.insert(0, sec.clone());
                        self.policy.insert(rule);
                    }
                }
            }
        }

        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.policy.clear();
        self.is_filtered = false;
        Ok(())
    }

    async fn add_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        mut rule: Vec<String>,
    ) -> Result<bool> {
        rule.insert(0, ptype.to_owned());
        rule.insert(0, sec.to_owned());

        Ok(self.policy.insert(rule))
    }

    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut all_added = true;
        let rules: Vec<Vec<String>> = rules
            .into_iter()
            .map(|mut rule| {
                rule.insert(0, ptype.to_owned());
                rule.insert(0, sec.to_owned());
                rule
            })
            .collect();

        for rule in &rules {
            if self.policy.contains(rule) {
                all_added = false;
                return Ok(all_added);
            }
        }
        self.policy.extend(rules);

        Ok(all_added)
    }

    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut all_removed = true;
        let rules: Vec<Vec<String>> = rules
            .into_iter()
            .map(|mut rule| {
                rule.insert(0, ptype.to_owned());
                rule.insert(0, sec.to_owned());
                rule
            })
            .collect();

        for rule in &rules {
            if !self.policy.contains(rule) {
                all_removed = false;
                return Ok(all_removed);
            }
        }
        for rule in &rules {
            self.policy.remove(rule);
        }

        Ok(all_removed)
    }

    async fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        mut rule: Vec<String>,
    ) -> Result<bool> {
        rule.insert(0, ptype.to_owned());
        rule.insert(0, sec.to_owned());

        Ok(self.policy.remove(&rule))
    }

    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_values.is_empty() {
            return Ok(false);
        }

        let mut tmp = LinkedHashSet::new();
        let mut res = false;
        for rule in &self.policy {
            if sec == rule[0] && ptype == rule[1] {
                let mut matched = true;
                for (i, field_value) in field_values.iter().enumerate() {
                    if !field_value.is_empty()
                        && &rule[field_index + i + 2] != field_value
                    {
                        matched = false;
                        break;
                    }
                }

                if matched {
                    res = true;
                } else {
                    tmp.insert(rule.clone());
                }
            } else {
                tmp.insert(rule.clone());
            }
        }
        self.policy = tmp;

        Ok(res)
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
}
