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

use crate::cache::Cache;
use mini_moka::sync::Cache as MokaCache;
use std::hash::Hash;

pub struct DefaultCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    cache: MokaCache<K, V>,
}

impl<K, V> DefaultCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    pub fn new(cap: usize) -> DefaultCache<K, V> {
        DefaultCache {
            cache: MokaCache::new(cap as u64),
        }
    }
}

impl<K, V> Cache<K, V> for DefaultCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    fn get(&self, k: &K) -> Option<V> {
        self.cache.get(k)
    }

    fn has(&self, k: &K) -> bool {
        self.cache.contains_key(k)
    }

    fn set(&self, k: K, v: V) {
        self.cache.insert(k, v);
    }

    fn clear(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(all(test, feature = "cached"))]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let cache = DefaultCache::new(1);

        cache.set(vec!["alice", "/data1", "read"], false);
        assert!(cache.get(&vec!["alice", "/data1", "read"]) == Some(false));
    }

    #[test]
    fn test_has_and_clear() {
        let cache = DefaultCache::new(1);

        cache.set(vec!["alice", "/data1", "read"], false);
        assert!(cache.has(&vec!["alice", "/data1", "read"]));
        cache.clear();
        assert!(!cache.has(&vec!["alice", "/data1", "read"]));
    }
}
