use crate::{MgmtApi, Result};

use async_trait::async_trait;

use std::collections::HashSet;

#[async_trait]
pub trait RbacApi: MgmtApi {
    async fn add_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool>;
    async fn add_permissions_for_user(
        &mut self,
        user: &str,
        permissions: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn add_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn add_roles_for_user(
        &mut self,
        user: &str,
        roles: Vec<String>,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn delete_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn delete_roles_for_user(
        &mut self,
        user: &str,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn delete_user(&mut self, name: &str) -> Result<bool>;
    async fn delete_role(&mut self, name: &str) -> Result<bool>;

    async fn delete_permission(
        &mut self,
        permission: Vec<String>,
    ) -> Result<bool> {
        self.remove_filtered_policy(1, permission).await
    }
    async fn delete_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool>;

    async fn delete_permissions_for_user(
        &mut self,
        user: &str,
    ) -> Result<bool> {
        self.remove_filtered_policy(
            0,
            [user].iter().map(|s| (*s).to_string()).collect(),
        )
        .await
    }

    fn get_roles_for_user(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<String>;
    fn get_users_for_role(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<String>;
    fn has_role_for_user(
        &self,
        name: &str,
        role: &str,
        domain: Option<&str>,
    ) -> bool;
    fn get_permissions_for_user(
        &self,
        user: &str,
        domain: Option<&str>,
    ) -> Vec<Vec<String>>;
    fn has_permission_for_user(
        &self,
        user: &str,
        permission: Vec<String>,
    ) -> bool;
    fn get_implicit_roles_for_user(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<String>;
    fn get_implicit_permissions_for_user(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<Vec<String>>;
    async fn get_implicit_users_for_permission(
        &self,
        permission: Vec<String>,
    ) -> Vec<String>;
}

#[async_trait]
impl<T> RbacApi for T
where
    T: MgmtApi,
{
    async fn add_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool> {
        let mut perm = permission;
        perm.insert(0, user.to_string());
        self.add_policy(perm).await
    }

    async fn add_permissions_for_user(
        &mut self,
        user: &str,
        permissions: Vec<Vec<String>>,
    ) -> Result<bool> {
        let perms = permissions
            .into_iter()
            .map(|mut p| {
                p.insert(0, user.to_string());
                p
            })
            .collect();
        self.add_policies(perms).await
    }

    async fn add_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.add_grouping_policy(if let Some(domain) = domain {
            [user, role, domain]
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            [user, role].iter().map(|s| (*s).to_string()).collect()
        })
        .await
    }

    async fn add_roles_for_user(
        &mut self,
        user: &str,
        roles: Vec<String>,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.add_grouping_policies(
            roles
                .into_iter()
                .map(|role| {
                    if let Some(domain) = domain {
                        vec![user.to_string(), role, domain.to_string()]
                    } else {
                        vec![user.to_string(), role]
                    }
                })
                .collect(),
        )
        .await
    }

    async fn delete_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.remove_grouping_policy(if let Some(domain) = domain {
            [user, role, domain]
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            [user, role].iter().map(|s| (*s).to_string()).collect()
        })
        .await
    }

    async fn delete_roles_for_user(
        &mut self,
        user: &str,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.remove_filtered_grouping_policy(
            0,
            if let Some(domain) = domain {
                [user, "", domain]
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                [user].iter().map(|s| (*s).to_string()).collect()
            },
        )
        .await
    }

    fn get_roles_for_user(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<String> {
        let mut roles = vec![];
        if let Some(t1) = self.get_model().get_model().get("g") {
            if let Some(t2) = t1.get("g") {
                roles = t2.rm.read().get_roles(name, domain);
            }
        }

        roles
    }

    fn get_users_for_role(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<String> {
        if let Some(t1) = self.get_model().get_model().get("g") {
            if let Some(t2) = t1.get("g") {
                return t2.rm.read().get_users(name, domain);
            }
        }
        vec![]
    }

    fn has_role_for_user(
        &self,
        name: &str,
        role: &str,
        domain: Option<&str>,
    ) -> bool {
        let roles = self.get_roles_for_user(name, domain);
        let mut has_role = false;
        for r in roles {
            if r == role {
                has_role = true;
                break;
            }
        }
        has_role
    }

    async fn delete_user(&mut self, name: &str) -> Result<bool> {
        let res1 = self
            .remove_filtered_grouping_policy(0, vec![name.to_string()])
            .await?;
        let res2 = self
            .remove_filtered_policy(0, vec![name.to_string()])
            .await?;
        Ok(res1 || res2)
    }

    async fn delete_role(&mut self, name: &str) -> Result<bool> {
        let res1 = self
            .remove_filtered_grouping_policy(1, vec![name.to_string()])
            .await?;
        let res2 = self
            .remove_filtered_policy(0, vec![name.to_string()])
            .await?;
        Ok(res1 || res2)
    }

    async fn delete_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool> {
        let mut permission = permission;
        permission.insert(0, user.to_string());
        self.remove_policy(permission).await
    }

    fn get_permissions_for_user(
        &self,
        user: &str,
        domain: Option<&str>,
    ) -> Vec<Vec<String>> {
        self.get_filtered_policy(0, {
            if let Some(domain) = domain {
                [user, domain].iter().map(|s| (*s).to_string()).collect()
            } else {
                [user].iter().map(|s| (*s).to_string()).collect()
            }
        })
    }

    fn has_permission_for_user(
        &self,
        user: &str,
        permission: Vec<String>,
    ) -> bool {
        let mut permission = permission;
        permission.insert(0, user.to_string());
        self.has_policy(permission)
    }

    fn get_implicit_roles_for_user(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<String> {
        let mut res: HashSet<String> = HashSet::new();
        let mut q: Vec<String> = vec![name.to_owned()];
        while !q.is_empty() {
            let name = q.swap_remove(0);
            let roles = self.get_role_manager().read().get_roles(&name, domain);
            for r in roles.into_iter() {
                if res.insert(r.to_owned()) {
                    q.push(r);
                }
            }
        }
        res.into_iter().collect()
    }

    fn get_implicit_permissions_for_user(
        &self,
        user: &str,
        domain: Option<&str>,
    ) -> Vec<Vec<String>> {
        let mut roles = self.get_implicit_roles_for_user(user, domain);
        roles.insert(0, user.to_owned());

        let mut res = vec![];

        for role in roles.iter() {
            let permissions = self.get_permissions_for_user(role, domain);
            res.extend(permissions);
        }
        res
    }

    async fn get_implicit_users_for_permission(
        &self,
        permission: Vec<String>,
    ) -> Vec<String> {
        let mut subjects = self.get_all_subjects();
        let roles = self.get_all_roles();

        subjects.extend(roles.iter().flat_map(|role| {
            self.get_role_manager().read().get_users(role, None)
        }));

        let users: Vec<String> = subjects
            .into_iter()
            .filter(|subject| !roles.contains(subject))
            .collect();

        let mut res: Vec<String> = vec![];
        for user in users.iter() {
            let mut req = permission.clone();
            req.insert(0, user.to_string());
            if let Ok(r) = self.enforce(req) {
                if r && !res.contains(user) {
                    res.push(user.to_owned());
                }
            }
        }
        res
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
    async fn test_role_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("non_exists", None)
        );

        assert_eq!(false, e.has_role_for_user("alice", "data1_admin", None));
        assert_eq!(true, e.has_role_for_user("alice", "data2_admin", None));

        e.add_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        assert_eq!(
            vec!["data1_admin", "data2_admin"],
            sort_unstable(e.get_roles_for_user("alice", None))
        );
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.delete_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.delete_roles_for_user("alice", None).await.unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.add_roles_for_user(
            "bob",
            vec!["data1_admin", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(
            vec!["data1_admin", "data2_admin"],
            sort_unstable(e.get_roles_for_user("bob", None))
        );

        e.delete_roles_for_user("bob", None).await.unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));

        e.add_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        e.delete_user("alice").await.unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.add_role_for_user("alice", "data2_admin", None)
            .await
            .unwrap();
        assert_eq!(false, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());

        e.delete_role("data2_admin").await.unwrap();
        assert_eq!(false, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "read")).unwrap());
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
    async fn test_role_api_threads() {
        use parking_lot::RwLock;

        use std::sync::Arc;
        use std::thread;

        #[cfg(feature = "runtime-async-std")]
        use async_std::task;

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Arc::new(RwLock::new(Enforcer::new(m, adapter).await.unwrap()));
        let ee = e.clone();

        assert_eq!(
            vec!["data2_admin"],
            e.write().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("data2_admin", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("non_exists", None)
        );

        assert_eq!(
            false,
            e.write().has_role_for_user("alice", "data1_admin", None)
        );
        assert_eq!(
            true,
            e.write().has_role_for_user("alice", "data2_admin", None)
        );

        thread::spawn(move || {
            #[cfg(feature = "runtime-async-std")]
            {
                task::block_on(async move {
                    ee.write()
                        .add_role_for_user("alice", "data1_admin", None)
                        .await
                        .unwrap();

                    assert_eq!(
                        vec!["data1_admin", "data2_admin"],
                        sort_unstable(
                            ee.write().get_roles_for_user("alice", None)
                        )
                    );
                    assert_eq!(
                        vec![String::new(); 0],
                        ee.write().get_roles_for_user("bob", None)
                    );
                    assert_eq!(
                        vec![String::new(); 0],
                        ee.write().get_roles_for_user("data2_admin", None)
                    );

                    ee.write()
                        .add_roles_for_user(
                            "bob",
                            vec!["data2_admin"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            None,
                        )
                        .await
                        .unwrap();

                    assert_eq!(
                        vec!["data1_admin", "data2_admin"],
                        sort_unstable(
                            ee.write().get_roles_for_user("alice", None)
                        )
                    );
                    assert_eq!(
                        vec!["data2_admin"],
                        ee.write().get_roles_for_user("bob", None)
                    );
                    assert_eq!(
                        vec![String::new(); 0],
                        ee.write().get_roles_for_user("data2_admin", None)
                    );
                });
            }

            #[cfg(feature = "runtime-tokio")]
            {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        ee.write()
                            .add_role_for_user("alice", "data1_admin", None)
                            .await
                            .unwrap();

                        assert_eq!(
                            vec!["data1_admin", "data2_admin"],
                            sort_unstable(
                                ee.write().get_roles_for_user("alice", None)
                            )
                        );
                        assert_eq!(
                            vec![String::new(); 0],
                            ee.write().get_roles_for_user("bob", None)
                        );
                        assert_eq!(
                            vec![String::new(); 0],
                            ee.write().get_roles_for_user("data2_admin", None)
                        );

                        ee.write()
                            .add_roles_for_user(
                                "bob",
                                vec!["data2_admin".to_owned()],
                                None,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            vec!["data1_admin", "data2_admin"],
                            sort_unstable(
                                ee.write().get_roles_for_user("alice", None)
                            )
                        );
                        assert_eq!(
                            vec!["data2_admin"],
                            ee.write().get_roles_for_user("bob", None)
                        );
                        assert_eq!(
                            vec![String::new(); 0],
                            ee.write().get_roles_for_user("data2_admin", None)
                        );
                    });
            }
        })
        .join()
        .unwrap();

        e.write()
            .delete_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        e.write().delete_roles_for_user("bob", None).await.unwrap();
        assert_eq!(
            vec!["data2_admin"],
            e.write().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("data2_admin", None)
        );

        e.write()
            .delete_roles_for_user("alice", None)
            .await
            .unwrap();
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("data2_admin", None)
        );

        e.write()
            .add_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        e.write().delete_user("alice").await.unwrap();
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().get_roles_for_user("data2_admin", None)
        );

        e.write()
            .add_role_for_user("alice", "data2_admin", None)
            .await
            .unwrap();
        assert_eq!(
            false,
            e.write().enforce(("alice", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.write().enforce(("alice", "data1", "write")).unwrap()
        );
        assert_eq!(
            true,
            e.write().enforce(("alice", "data2", "read")).unwrap()
        );
        assert_eq!(
            true,
            e.write().enforce(("alice", "data2", "write")).unwrap()
        );
        assert_eq!(false, e.write().enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(
            false,
            e.write().enforce(("bob", "data1", "write")).unwrap()
        );
        assert_eq!(false, e.write().enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.write().enforce(("bob", "data2", "write")).unwrap());

        e.write().delete_role("data2_admin").await.unwrap();
        assert_eq!(
            false,
            e.write().enforce(("alice", "data1", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.write().enforce(("alice", "data1", "write")).unwrap()
        );
        assert_eq!(
            false,
            e.write().enforce(("alice", "data2", "read")).unwrap()
        );
        assert_eq!(
            false,
            e.write().enforce(("alice", "data2", "write")).unwrap()
        );
        assert_eq!(false, e.write().enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(
            false,
            e.write().enforce(("bob", "data1", "write")).unwrap()
        );
        assert_eq!(false, e.write().enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.write().enforce(("bob", "data2", "write")).unwrap());
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
    async fn test_permission_api() {
        let m = DefaultModel::from_file(
            "examples/basic_without_resources_model.conf",
        )
        .await
        .unwrap();

        let adapter =
            FileAdapter::new("examples/basic_without_resources_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(true, e.enforce(("alice", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "write")).unwrap());

        assert_eq!(
            vec![vec!["alice", "read"]],
            e.get_permissions_for_user("alice", None)
        );
        assert_eq!(
            vec![vec!["bob", "write"]],
            e.get_permissions_for_user("bob", None)
        );

        assert_eq!(
            true,
            e.has_permission_for_user(
                "alice",
                vec!["read"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            false,
            e.has_permission_for_user(
                "alice",
                vec!["write"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            false,
            e.has_permission_for_user(
                "bob",
                vec!["read"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            true,
            e.has_permission_for_user(
                "bob",
                vec!["write"].iter().map(|s| s.to_string()).collect()
            )
        );

        e.delete_permission(
            vec!["read"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();

        assert_eq!(false, e.enforce(("alice", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "write")).unwrap());

        e.add_permission_for_user(
            "bob",
            vec!["read"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();
        e.add_permissions_for_user(
            "eve",
            vec![
                vec!["read"].iter().map(|s| s.to_string()).collect(),
                vec!["write"].iter().map(|s| s.to_string()).collect(),
            ],
        )
        .await
        .unwrap();

        assert_eq!(false, e.enforce(("alice", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "write")).unwrap());
        assert_eq!(true, e.enforce(("bob", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "write")).unwrap());
        assert_eq!(true, e.enforce(("eve", "read")).unwrap());
        assert_eq!(true, e.enforce(("eve", "write")).unwrap());

        e.delete_permission_for_user(
            "bob",
            vec!["read"].iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();

        assert_eq!(false, e.enforce(("alice", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "write")).unwrap());
        assert_eq!(true, e.enforce(("eve", "read")).unwrap());
        assert_eq!(true, e.enforce(("eve", "write")).unwrap());

        e.delete_permissions_for_user("bob").await.unwrap();
        e.delete_permissions_for_user("eve").await.unwrap();

        assert_eq!(false, e.enforce(("alice", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "write")).unwrap());
        assert_eq!(false, e.enforce(("eve", "read")).unwrap());
        assert_eq!(false, e.enforce(("eve", "write")).unwrap());
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
    async fn test_implicit_role_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter =
            FileAdapter::new("examples/rbac_with_hierarchy_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_permissions_for_user("alice", None)
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_permissions_for_user("bob", None)
        );

        assert_eq!(
            vec!["admin", "data1_admin", "data2_admin"],
            sort_unstable(e.get_implicit_roles_for_user("alice", None))
        );
        assert_eq!(
            vec![String::new(); 0],
            e.get_implicit_roles_for_user("bob", None)
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
    async fn test_implicit_permission_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter =
            FileAdapter::new("examples/rbac_with_hierarchy_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_permissions_for_user("alice", None)
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_permissions_for_user("bob", None)
        );

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["data1_admin", "data1", "read"],
                vec!["data1_admin", "data1", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_implicit_permissions_for_user("alice", None))
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_implicit_permissions_for_user("bob", None)
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
    async fn test_implicit_user_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter =
            FileAdapter::new("examples/rbac_with_hierarchy_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec!["alice"],
            e.get_implicit_users_for_permission(
                vec!["data1", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
            .await
        );
        assert_eq!(
            vec!["alice"],
            e.get_implicit_users_for_permission(
                vec!["data1", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
            .await
        );
        assert_eq!(
            vec!["alice"],
            e.get_implicit_users_for_permission(
                vec!["data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
            .await
        );
        assert_eq!(
            vec!["alice", "bob"],
            sort_unstable(
                e.get_implicit_users_for_permission(
                    vec!["data2", "write"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                )
                .await
            )
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
    async fn test_implicit_permission_api_with_domain() {
        let m =
            DefaultModel::from_file("examples/rbac_with_domains_model.conf")
                .await
                .unwrap();

        let adapter = FileAdapter::new(
            "examples/rbac_with_hierarchy_with_domains_policy.csv",
        );
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "domain1", "data2", "read"],
                vec!["role:reader", "domain1", "data1", "read"],
                vec!["role:writer", "domain1", "data1", "write"],
            ],
            sort_unstable(
                e.get_implicit_permissions_for_user("alice", Some("domain1"))
            )
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
    async fn test_pattern_matching_fn() {
        let e = Enforcer::new(
            "examples/rbac_with_pattern_model.conf",
            "examples/rbac_with_pattern_policy.csv",
        )
        .await
        .unwrap();

        use crate::model::key_match2;

        e.get_named_role_manager("g2")
            .unwrap()
            .write()
            .matching_fn(Some(key_match2), None);

        assert!(e.enforce(("alice", "/pen/1", "GET")).unwrap());
        assert!(e.enforce(("alice", "/pen2/1", "GET")).unwrap());
        assert!(e.enforce(("alice", "/book/1", "GET")).unwrap());
        assert!(e.enforce(("alice", "/book/2", "GET")).unwrap());
        assert!(e.enforce(("alice", "/pen/1", "GET")).unwrap());
        assert!(!e.enforce(("alice", "/pen/2", "GET")).unwrap());
        assert!(!e.enforce(("bob", "/book/1", "GET")).unwrap());
        assert!(!e.enforce(("bob", "/book/2", "GET")).unwrap());
        assert!(e.enforce(("bob", "/pen/1", "GET")).unwrap());
        assert!(e.enforce(("bob", "/pen/2", "GET")).unwrap());

        let rm = e.get_named_role_manager("g2").unwrap();
        assert_eq!(vec!["book_group"], rm.read().get_roles("/book/1", None));
        assert_eq!(vec!["pen_group"], rm.read().get_roles("/pen/1", None));
        assert!(e.get_implicit_roles_for_user("/book/1", None).is_empty());
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
    async fn test_pattern_matching_fn_with_domain() {
        let e = Enforcer::new(
            "examples/rbac_with_pattern_domain_model.conf",
            "examples/rbac_with_pattern_domain_policy.csv",
        )
        .await
        .unwrap();

        use crate::function_map::key_match;

        e.get_role_manager()
            .write()
            .matching_fn(None, Some(key_match));

        assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap());
        assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
        assert!(e.enforce(("alice", "domain2", "data2", "read")).unwrap());
        assert!(e.enforce(("alice", "domain2", "data2", "write")).unwrap());

        assert!(!e.enforce(("bob", "domain1", "data1", "read")).unwrap());
        assert!(!e.enforce(("bob", "domain1", "data1", "write")).unwrap());
        assert!(e.enforce(("bob", "domain2", "data2", "read")).unwrap());
        assert!(e.enforce(("bob", "domain2", "data2", "write")).unwrap());

        assert_eq!(
            vec!["admin".to_owned()],
            e.get_implicit_roles_for_user("alice", Some("domain3"))
        );

        assert_eq!(
            vec!["alice".to_owned()],
            e.get_users_for_role("admin", Some("domain3"))
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
    async fn test_pattern_matching_basic_role() {
        let e = Enforcer::new(
            "examples/rbac_basic_role_model.conf",
            "examples/rbac_basic_role_policy.csv",
        )
        .await
        .unwrap();

        use crate::model::key_match;

        e.get_role_manager()
            .write()
            .matching_fn(Some(key_match), None);

        assert!(e.enforce(("alice", "/pen/1", "GET")).unwrap());
        assert!(e.enforce(("alice", "/book/1", "GET")).unwrap());
        assert!(e.enforce(("bob", "/pen/1", "GET")).unwrap());
        assert!(e.enforce(("bob", "/book/1", "GET")).unwrap());

        assert!(!e.enforce(("alice", "/pen/2", "GET")).unwrap());
        assert!(!e.enforce(("alice", "/book/2", "GET")).unwrap());
        assert!(!e.enforce(("bob", "/pen/2", "GET")).unwrap());
        assert!(!e.enforce(("bob", "/book/2", "GET")).unwrap());

        assert_eq!(
            vec!["book_admin", "pen_admin"],
            sort_unstable(e.get_implicit_roles_for_user("alice", None))
        );
        assert_eq!(
            vec!["book_admin", "pen_admin"],
            sort_unstable(e.get_implicit_roles_for_user("bob", None))
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
    async fn test_implicit_users_for_permission() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && regexMatch(r.act, p.act)",
        );

        let a = MemoryAdapter::default();

        let mut e = Enforcer::new(m, a).await.unwrap();

        assert!(e
            .add_policy(vec![
                "role::r1".to_owned(),
                "data1".to_owned(),
                "(read)|(writer)".to_owned()
            ])
            .await
            .unwrap());

        assert!(e
            .add_policy(vec![
                "role::r2".to_owned(),
                "data2".to_owned(),
                "writer".to_owned()
            ])
            .await
            .unwrap());

        assert!(e
            .add_policy(vec![
                "user1".to_owned(),
                "data2".to_owned(),
                "writer".to_owned()
            ])
            .await
            .unwrap());

        assert!(e
            .add_grouping_policy(vec![
                "user2".to_owned(),
                "role::r2".to_owned(),
            ])
            .await
            .unwrap());

        assert!(e
            .add_grouping_policy(vec![
                "user3".to_owned(),
                "role::r2".to_owned(),
            ])
            .await
            .unwrap());

        assert_eq!(
            vec!["user1".to_owned(), "user2".to_owned(), "user3".to_owned()],
            sort_unstable(
                e.get_implicit_users_for_permission(vec![
                    "data2".to_owned(),
                    "writer".to_owned()
                ])
                .await
            )
        );
    }
}
