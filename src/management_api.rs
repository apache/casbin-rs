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

use crate::{InternalApi, Result};

use async_trait::async_trait;

#[async_trait]
pub trait MgmtApi: InternalApi {
    async fn add_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.add_named_policy("p", params).await
    }

    async fn add_policies(
        &mut self,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.add_named_policies("p", paramss).await
    }

    async fn remove_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.remove_named_policy("p", params).await
    }

    async fn remove_policies(
        &mut self,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.remove_named_policies("p", paramss).await
    }

    async fn add_named_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool>;
    async fn add_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_named_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool>;
    async fn remove_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;

    async fn add_grouping_policy(
        &mut self,
        params: Vec<String>,
    ) -> Result<bool> {
        self.add_named_grouping_policy("g", params).await
    }

    async fn add_grouping_policies(
        &mut self,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.add_named_grouping_policies("g", paramss).await
    }

    async fn remove_grouping_policy(
        &mut self,
        params: Vec<String>,
    ) -> Result<bool> {
        self.remove_named_grouping_policy("g", params).await
    }

    async fn remove_grouping_policies(
        &mut self,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.remove_named_grouping_policies("g", paramss).await
    }

    async fn add_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool>;
    async fn add_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool>;
    async fn remove_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;

    async fn remove_filtered_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.remove_filtered_named_policy("p", field_index, field_values)
            .await
    }

    async fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.remove_filtered_named_grouping_policy(
            "g",
            field_index,
            field_values,
        )
        .await
    }

    async fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
    async fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;

    fn get_policy(&self) -> Vec<Vec<String>> {
        self.get_named_policy("p")
    }

    fn get_all_policy(&self) -> Vec<Vec<String>>;
    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>>;

    fn get_filtered_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.get_filtered_named_policy("p", field_index, field_values)
    }

    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;

    fn has_policy(&self, params: Vec<String>) -> bool {
        self.has_named_policy("p", params)
    }

    fn has_named_policy(&self, ptype: &str, params: Vec<String>) -> bool;

    fn get_grouping_policy(&self) -> Vec<Vec<String>> {
        self.get_named_grouping_policy("g")
    }

    fn get_all_grouping_policy(&self) -> Vec<Vec<String>>;
    fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>>;

    fn get_filtered_grouping_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.get_filtered_named_grouping_policy("g", field_index, field_values)
    }

    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn has_grouping_policy(&self, params: Vec<String>) -> bool {
        self.has_grouping_named_policy("g", params)
    }
    fn has_grouping_named_policy(
        &self,
        ptype: &str,
        params: Vec<String>,
    ) -> bool;

    fn get_all_subjects(&self) -> Vec<String> {
        self.get_all_named_subjects("p")
    }

    fn get_all_named_subjects(&self, ptype: &str) -> Vec<String>;

    fn get_all_objects(&self) -> Vec<String> {
        self.get_all_named_objects("p")
    }

    fn get_all_named_objects(&self, ptype: &str) -> Vec<String>;

    fn get_all_actions(&self) -> Vec<String> {
        self.get_all_named_actions("p")
    }

    fn get_all_roles(&self) -> Vec<String> {
        self.get_all_named_roles("g")
    }

    fn get_all_named_actions(&self, ptype: &str) -> Vec<String>;

    fn get_all_named_roles(&self, ptype: &str) -> Vec<String>;
}

#[async_trait]
impl<T> MgmtApi for T
where
    T: InternalApi,
{
    async fn add_named_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        self.add_policy_internal("p", ptype, params).await
    }

    async fn add_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.add_policies_internal("p", ptype, paramss).await
    }

    async fn remove_named_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        self.remove_policy_internal("p", ptype, params).await
    }

    async fn remove_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.remove_policies_internal("p", ptype, paramss).await
    }

    async fn add_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        let rule_added = self.add_policy_internal("g", ptype, params).await?;
        Ok(rule_added)
    }

    async fn add_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_added = self.add_policies_internal("g", ptype, paramss).await?;
        Ok(all_added)
    }

    async fn remove_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        let rule_removed =
            self.remove_policy_internal("g", ptype, params).await?;
        Ok(rule_removed)
    }

    async fn remove_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_removed =
            self.remove_policies_internal("g", ptype, paramss).await?;
        Ok(all_removed)
    }

    async fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        #[allow(unused_variables)]
        let (rule_removed, rules) = self
            .remove_filtered_policy_internal(
                "g",
                ptype,
                field_index,
                field_values,
            )
            .await?;
        Ok(rule_removed)
    }

    async fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        Ok(self
            .remove_filtered_policy_internal(
                "p",
                ptype,
                field_index,
                field_values,
            )
            .await?
            .0)
    }

    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.get_model().get_policy("p", ptype)
    }

    fn get_all_policy(&self) -> Vec<Vec<String>> {
        let mut res: Vec<Vec<String>> = vec![];
        let sec = "p";
        if let Some(ast_map) = self.get_model().get_model().get(sec) {
            for (ptype, ast) in ast_map {
                res.extend(ast.get_policy().clone().into_iter().map(|mut x| {
                    x.insert(0, ptype.clone());
                    x.insert(0, sec.to_owned());
                    x
                }))
            }
        }

        res
    }

    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.get_model().get_filtered_policy(
            "p",
            ptype,
            field_index,
            field_values,
        )
    }

    fn has_named_policy(&self, ptype: &str, params: Vec<String>) -> bool {
        self.get_model().has_policy("p", ptype, params)
    }

    fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.get_model().get_policy("g", ptype)
    }

    fn get_all_grouping_policy(&self) -> Vec<Vec<String>> {
        let mut res: Vec<Vec<String>> = vec![];
        let sec = "g";
        if let Some(ast_map) = self.get_model().get_model().get(sec) {
            for (ptype, ast) in ast_map {
                res.extend(ast.get_policy().clone().into_iter().map(|mut x| {
                    x.insert(0, ptype.clone());
                    x.insert(0, sec.to_owned());
                    x
                }))
            }
        }

        res
    }

    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.get_model().get_filtered_policy(
            "g",
            ptype,
            field_index,
            field_values,
        )
    }

    fn has_grouping_named_policy(
        &self,
        ptype: &str,
        params: Vec<String>,
    ) -> bool {
        self.get_model().has_policy("g", ptype, params)
    }

    fn get_all_named_subjects(&self, ptype: &str) -> Vec<String> {
        self.get_model()
            .get_values_for_field_in_policy("p", ptype, 0)
    }

    fn get_all_named_objects(&self, ptype: &str) -> Vec<String> {
        self.get_model()
            .get_values_for_field_in_policy("p", ptype, 1)
    }

    fn get_all_named_actions(&self, ptype: &str) -> Vec<String> {
        self.get_model()
            .get_values_for_field_in_policy("p", ptype, 2)
    }

    fn get_all_named_roles(&self, ptype: &str) -> Vec<String> {
        self.get_model()
            .get_values_for_field_in_policy("g", ptype, 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort_unstable();
        v
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
    async fn test_modify_grouping_policy_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("bob", None));
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("eve", None));
        assert_eq!(
            Vec::<String>::new(),
            e.get_roles_for_user("non_exist", None)
        );

        e.remove_grouping_policy(
            ["alice", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            ["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            ["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        let named_grouping_policy =
            vec!["alice".to_string(), "data2_admin".to_string()];
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("alice", None));
        e.add_named_grouping_policy("g", named_grouping_policy.clone())
            .await
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        e.remove_named_grouping_policy("g", named_grouping_policy.clone())
            .await
            .unwrap();

        e.remove_grouping_policy(
            ["alice", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            ["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            ["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(vec!["bob"], e.get_users_for_role("data1_admin", None));
        assert_eq!(
            Vec::<String>::new(),
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));

        e.remove_filtered_grouping_policy(
            0,
            ["bob"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();

        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("alice", None));
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("bob", None));
        assert_eq!(vec!["data3_admin"], e.get_roles_for_user("eve", None));
        assert_eq!(
            Vec::<String>::new(),
            e.get_roles_for_user("non_exist", None)
        );

        assert_eq!(
            Vec::<String>::new(),
            e.get_users_for_role("data1_admin", None)
        );
        assert_eq!(
            Vec::<String>::new(),
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));
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
    async fn test_modify_policy_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_policy(
            ["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.remove_policy(
            ["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.remove_policy(
            ["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            ["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            ["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        let named_policy =
            vec!["eve".to_string(), "data3".to_string(), "read".to_string()];
        e.remove_named_policy("p", named_policy.clone())
            .await
            .unwrap();
        e.add_named_policy("p", named_policy.clone()).await.unwrap();

        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
                vec!["eve", "data3", "read"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_filtered_policy(
            1,
            ["data2"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();
        assert_eq!(vec![vec!["eve", "data3", "read"],], e.get_policy());
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
    async fn test_get_policy_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_policy())
        );

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_filtered_policy(
                0,
                ["alice"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_filtered_policy(
                0,
                ["bob"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_filtered_policy(
                0,
                ["data2_admin"].iter().map(|s| s.to_string()).collect()
            ))
        );
        assert_eq!(
            vec![vec!["alice", "data1", "read"],],
            e.get_filtered_policy(
                1,
                ["data1"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_filtered_policy(
                1,
                ["data2"].iter().map(|s| s.to_string()).collect()
            ))
        );
        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["data2_admin", "data2", "read"],
            ],
            sort_unstable(e.get_filtered_policy(
                2,
                ["read"].iter().map(|s| s.to_string()).collect()
            ))
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_filtered_policy(
                2,
                ["write"].iter().map(|s| s.to_string()).collect()
            ))
        );
        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(
                e.get_filtered_policy(
                    0,
                    ["data2_admin", "data2"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                )
            )
        );
        // Note: "" (empty string) in fieldValues means matching all values.
        assert_eq!(
            vec![vec!["data2_admin", "data2", "read"],],
            e.get_filtered_policy(
                0,
                ["data2_admin", "", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_filtered_policy(
                1,
                ["data2", "write"].iter().map(|s| s.to_string()).collect()
            ))
        );

        assert!(e.has_policy(
            ["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(e.has_policy(
            ["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(!e.has_policy(
            ["alice", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(!e.has_policy(
            ["bob", "data3", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));

        assert_eq!(
            vec![vec!["alice", "data2_admin"]],
            e.get_filtered_grouping_policy(
                0,
                ["alice"].iter().map(|s| s.to_string()).collect()
            )
        );
        let empty_policy: Vec<Vec<String>> = vec![];
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(
                0,
                ["bob"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(
                1,
                ["data1_admin"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            vec![vec!["alice", "data2_admin"],],
            e.get_filtered_grouping_policy(
                1,
                ["data2_admin"].iter().map(|s| s.to_string()).collect()
            )
        );
        // Note: "" (empty string) in fieldValues means matching all values.
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(
                0,
                ["data2_admin"].iter().map(|s| s.to_string()).collect()
            )
        );

        assert!(e.has_grouping_policy(
            ["alice", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(!e.has_grouping_policy(
            ["bob", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
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
    async fn test_get_list() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec!["alice", "bob", "data2_admin"],
            sort_unstable(e.get_all_subjects())
        );
        assert_eq!(vec!["data1", "data2"], sort_unstable(e.get_all_objects()));
        assert_eq!(vec!["read", "write"], sort_unstable(e.get_all_actions()));
        assert_eq!(vec!["data2_admin"], e.get_all_roles());
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
    async fn test_modify_policies_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_policies(vec![
            ["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();
        e.remove_policies(vec![["alice", "data1", "read"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();
        assert!(!e.has_policy(
            ["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(!e.has_policy(
            ["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(e.has_policy(
            ["data2_admin", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(e.has_policy(
            ["data2_admin", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        e.add_policies(vec![["eve", "data3", "read"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();
        e.add_policies(vec![
            ["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();
        assert!(!e.has_policy(
            ["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(!e.has_policy(
            ["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(e.has_policy(
            ["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(e.has_policy(
            ["data2_admin", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));
        assert!(e.has_policy(
            ["data2_admin", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        ));

        let named_policy =
            vec!["eve".to_string(), "data3".to_string(), "read".to_string()];
        e.remove_named_policies("p", vec![named_policy.clone()])
            .await
            .unwrap();
        e.add_named_policies("p", vec![named_policy.clone()])
            .await
            .unwrap();

        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
                vec!["eve", "data3", "read"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_filtered_policy(
            1,
            ["data2"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();
        assert_eq!(vec![vec!["eve", "data3", "read"],], e.get_policy());
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
    async fn test_modify_grouping_policies_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("bob", None));
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("eve", None));
        assert_eq!(
            Vec::<String>::new(),
            e.get_roles_for_user("non_exist", None)
        );

        e.remove_grouping_policies(vec![["alice", "data2_admin"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();
        e.add_grouping_policies(vec![
            ["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("alice", None));
        assert_eq!(vec!["data1_admin"], e.get_roles_for_user("bob", None));
        assert_eq!(vec!["data3_admin"], e.get_roles_for_user("eve", None));

        let named_grouping_policy =
            vec!["alice".to_string(), "data2_admin".to_string()];
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("alice", None));
        e.add_named_grouping_policies("g", vec![named_grouping_policy.clone()])
            .await
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        e.remove_named_grouping_policies(
            "g",
            vec![named_grouping_policy.clone()],
        )
        .await
        .unwrap();

        e.remove_grouping_policies(vec![["alice", "data2_admin"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();

        e.add_grouping_policies(vec![
            ["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();

        assert_eq!(vec!["bob"], e.get_users_for_role("data1_admin", None));
        assert_eq!(
            Vec::<String>::new(),
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));

        e.remove_filtered_grouping_policy(
            0,
            ["bob"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();

        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("alice", None));
        assert_eq!(Vec::<String>::new(), e.get_roles_for_user("bob", None));
        assert_eq!(vec!["data3_admin"], e.get_roles_for_user("eve", None));
        assert_eq!(
            Vec::<String>::new(),
            e.get_roles_for_user("non_exist", None)
        );

        assert_eq!(
            Vec::<String>::new(),
            e.get_users_for_role("data1_admin", None)
        );
        assert_eq!(
            Vec::<String>::new(),
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));
    }
}
