use crate::emitter::EventData;

pub trait Watcher: Send + Sync {
    fn set_update_callback(&mut self, cb: Box<dyn FnMut(String) + Send + Sync>);
    fn update(&mut self, d: EventData);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use std::sync::{Arc, Mutex};

    // save_policy() rewrites the policy file, so give each test its own copy
    // instead of truncating the fixture other tests are reading concurrently.
    #[cfg(not(target_arch = "wasm32"))]
    fn temp_policy_file(name: &str) -> FileAdapter<std::path::PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "casbin_rs_{}_{}.csv",
            name,
            std::process::id()
        ));
        std::fs::copy("examples/rbac_policy.csv", &path).unwrap();
        FileAdapter::new(path)
    }

    // Sample watcher implementation for testing
    struct SampleWatcher {
        callback: Option<Box<dyn FnMut(String) + Send + Sync>>,
    }

    impl SampleWatcher {
        fn new() -> Self {
            SampleWatcher { callback: None }
        }
    }

    impl Watcher for SampleWatcher {
        fn set_update_callback(
            &mut self,
            cb: Box<dyn FnMut(String) + Send + Sync>,
        ) {
            self.callback = Some(cb);
        }

        fn update(&mut self, d: EventData) {
            if let Some(ref mut callback) = self.callback {
                callback(d.to_string());
            }
        }
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
    async fn test_set_watcher() {
        let mut e = Enforcer::new(
            "examples/rbac_model.conf",
            temp_policy_file("set_watcher"),
        )
        .await
        .unwrap();

        let sample_watcher = SampleWatcher::new();
        e.set_watcher(Box::new(sample_watcher));

        // calls watcher.update()
        e.save_policy().await.unwrap();
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
    async fn test_self_modify() {
        let mut e = Enforcer::new(
            "examples/rbac_model.conf",
            "examples/rbac_policy.csv",
        )
        .await
        .unwrap();

        let sample_watcher = SampleWatcher::new();
        e.set_watcher(Box::new(sample_watcher));

        // Test callback for add_policy (should be called)
        let called = Arc::new(Mutex::new(-1));
        let called_clone = Arc::clone(&called);

        if let Some(watcher) = e.get_mut_watcher() {
            watcher.set_update_callback(Box::new(move |_s: String| {
                let mut c = called_clone.lock().unwrap();
                *c = 1;
            }));
        }

        // calls watcher.update()
        let result = e
            .add_policy(vec![
                "eva".to_string(),
                "data".to_string(),
                "read".to_string(),
            ])
            .await;
        assert!(result.unwrap());

        let called_value = *called.lock().unwrap();
        assert_eq!(called_value, 1, "callback should be called");

        // Test callback for self_add_policy (should not be called for self operations)
        let called2 = Arc::new(Mutex::new(-1));
        let called2_clone = Arc::clone(&called2);

        if let Some(watcher) = e.get_mut_watcher() {
            watcher.set_update_callback(Box::new(move |_s: String| {
                let mut c = called2_clone.lock().unwrap();
                *c = 1;
            }));
        }

        // Note: casbin-rs doesn't have self_add_policy, using add_policy instead
        // This test demonstrates the watcher callback functionality
        let result = e
            .add_policy(vec![
                "eva".to_string(),
                "data".to_string(),
                "write".to_string(),
            ])
            .await;
        assert!(result.unwrap());

        // In casbin-rs, watcher is called for all policy changes
        let called2_value = *called2.lock().unwrap();
        assert_eq!(
            called2_value, 1,
            "callback should be called for policy changes"
        );
    }

    #[test]
    fn test_watcher_callback_with_event_data() {
        let mut sample_watcher = SampleWatcher::new();

        let called_data = Arc::new(Mutex::new(String::new()));
        let called_data_clone = Arc::clone(&called_data);

        sample_watcher.set_update_callback(Box::new(move |data: String| {
            let mut d = called_data_clone.lock().unwrap();
            *d = data;
        }));

        // Test with AddPolicy event
        let event_data = EventData::AddPolicy(
            "p".to_string(),
            "p".to_string(),
            vec!["alice".to_string(), "data1".to_string(), "read".to_string()],
        );

        sample_watcher.update(event_data);

        let result = called_data.lock().unwrap();
        assert!(result.contains("AddPolicy"));
        assert!(result.contains("alice"));
        assert!(result.contains("data1"));
        assert!(result.contains("read"));
    }

    // Sample extended watcher implementation for comprehensive testing
    struct SampleWatcherEx {
        callback: Option<Box<dyn FnMut(String) + Send + Sync>>,
        update_calls: Arc<Mutex<Vec<String>>>,
    }

    impl SampleWatcherEx {
        fn new() -> Self {
            SampleWatcherEx {
                callback: None,
                update_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Watcher for SampleWatcherEx {
        fn set_update_callback(
            &mut self,
            cb: Box<dyn FnMut(String) + Send + Sync>,
        ) {
            self.callback = Some(cb);
        }

        fn update(&mut self, d: EventData) {
            let event_str = d.to_string();

            // Record the update call
            self.update_calls.lock().unwrap().push(event_str.clone());

            // Call the callback if set
            if let Some(ref mut callback) = self.callback {
                callback(event_str);
            }
        }
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
    async fn test_set_watcher_ex() {
        let mut e = Enforcer::new(
            "examples/rbac_model.conf",
            temp_policy_file("set_watcher_ex"),
        )
        .await
        .unwrap();

        let sample_watcher_ex = SampleWatcherEx::new();
        let update_calls = Arc::clone(&sample_watcher_ex.update_calls);
        e.set_watcher(Box::new(sample_watcher_ex));

        // calls watcher.update() for SavePolicy
        e.save_policy().await.unwrap();

        // calls watcher.update() for AddPolicy
        let _ = e
            .add_policy(vec![
                "admin".to_string(),
                "data1".to_string(),
                "read".to_string(),
            ])
            .await;

        // calls watcher.update() for RemovePolicy
        let _ = e
            .remove_policy(vec![
                "admin".to_string(),
                "data1".to_string(),
                "read".to_string(),
            ])
            .await;

        // calls watcher.update() for RemoveFilteredPolicy
        let _ = e.remove_filtered_policy(1, vec!["data1".to_string()]).await;

        // calls watcher.update() for AddGroupingPolicy
        let _ = e
            .add_grouping_policy(vec![
                "g:admin".to_string(),
                "data1".to_string(),
            ])
            .await;

        // calls watcher.update() for RemoveGroupingPolicy
        let _ = e
            .remove_grouping_policy(vec![
                "g:admin".to_string(),
                "data1".to_string(),
            ])
            .await;

        // calls watcher.update() for AddGroupingPolicy again
        let _ = e
            .add_grouping_policy(vec![
                "g:admin".to_string(),
                "data1".to_string(),
            ])
            .await;

        // calls watcher.update() for RemoveFilteredGroupingPolicy
        let _ = e
            .remove_filtered_grouping_policy(1, vec!["data1".to_string()])
            .await;

        // calls watcher.update() for AddPolicies
        let _ = e
            .add_policies(vec![
                vec![
                    "admin".to_string(),
                    "data1".to_string(),
                    "read".to_string(),
                ],
                vec![
                    "admin".to_string(),
                    "data2".to_string(),
                    "read".to_string(),
                ],
            ])
            .await;

        // calls watcher.update() for RemovePolicies
        let _ = e
            .remove_policies(vec![
                vec![
                    "admin".to_string(),
                    "data1".to_string(),
                    "read".to_string(),
                ],
                vec![
                    "admin".to_string(),
                    "data2".to_string(),
                    "read".to_string(),
                ],
            ])
            .await;

        // Verify that watcher was called for all operations
        let calls = update_calls.lock().unwrap();
        assert!(!calls.is_empty(), "Watcher should have been called");

        // Verify some specific operation types were captured
        let call_types: Vec<String> = calls
            .iter()
            .filter_map(|call| {
                if call.contains("SavePolicy") {
                    Some("SavePolicy".to_string())
                } else if call.contains("AddPolicy") {
                    Some("AddPolicy".to_string())
                } else if call.contains("RemovePolicy") {
                    Some("RemovePolicy".to_string())
                } else if call.contains("AddPolicies") {
                    Some("AddPolicies".to_string())
                } else if call.contains("RemovePolicies") {
                    Some("RemovePolicies".to_string())
                } else {
                    None
                }
            })
            .collect();

        assert!(
            call_types.contains(&"SavePolicy".to_string()),
            "Should capture SavePolicy calls"
        );
        assert!(
            call_types.contains(&"AddPolicy".to_string()),
            "Should capture AddPolicy calls"
        );
        assert!(
            call_types.contains(&"RemovePolicy".to_string()),
            "Should capture RemovePolicy calls"
        );
    }
}
