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

#[cfg(any(feature = "watcher", feature = "cached", feature = "logging"))]
use crate::core_api::CoreApi;

#[cfg(feature = "cached")]
use crate::cached_api::CachedApi;

use std::{fmt, hash::Hash};

#[derive(Hash, PartialEq, Eq)]
pub enum Event {
    PolicyChange,
    ClearCache,
}

pub trait EventKey: Hash + PartialEq + Eq + Send + Sync {}
impl<T> EventKey for T where T: Hash + PartialEq + Eq + Send + Sync {}

#[derive(Clone)]
pub enum EventData {
    AddPolicy(String, String, Vec<String>),
    AddPolicies(String, String, Vec<Vec<String>>),
    RemovePolicy(String, String, Vec<String>),
    RemovePolicies(String, String, Vec<Vec<String>>),
    RemoveFilteredPolicy(String, String, Vec<Vec<String>>),
    SavePolicy(Vec<Vec<String>>),
    ClearPolicy,
    ClearCache,
}

impl fmt::Display for EventData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EventData::*;
        match *self {
            AddPolicy(ref sec, ref ptype, ref p) => write!(
                f,
                "Type: AddPolicy, Assertion: {}::{},  Data: {:?}",
                sec,
                ptype,
                p.join(", ")
            ),
            AddPolicies(ref sec, ref ptype, ref p) => write!(
                f,
                "Type: AddPolicies, Assertion: {}::{}, Added: {}",
                sec,
                ptype,
                p.len()
            ),
            RemovePolicy(ref sec, ref ptype, ref p) => write!(
                f,
                "Type: RemovePolicy, Assertion: {}::{}, Data: {:?}",
                sec,
                ptype,
                p.join(", ")
            ),
            RemovePolicies(ref sec, ref ptype, ref p) => write!(
                f,
                "Type: RemovePolicies, Assertion: {}::{}, Removed: {}",
                sec,
                ptype,
                p.len()
            ),
            RemoveFilteredPolicy(ref sec, ref ptype, ref p) => write!(
                f,
                "Type: RemoveFilteredPolicy, Assertion: {}::{}, Removed: {}",
                sec,
                ptype,
                p.len()
            ),
            SavePolicy(ref p) => {
                write!(f, "Type: SavePolicy, Saved: {}", p.len())
            }
            ClearPolicy => write!(f, "Type: ClearPolicy"),
            ClearCache => write!(f, "Type: ClearCache, Data: ClearCache"),
        }
    }
}

pub trait EventEmitter<K>
where
    K: EventKey,
{
    fn on(&mut self, e: K, f: fn(&mut Self, EventData))
    where
        Self: Sized;
    fn off(&mut self, e: K);
    fn emit(&mut self, e: K, d: EventData);
}

#[cfg(any(feature = "logging", feature = "watcher"))]
pub(crate) fn notify_logger_and_watcher<T: CoreApi>(e: &mut T, d: EventData) {
    #[cfg(feature = "logging")]
    {
        e.get_logger().print_mgmt_log(&d);
    }

    #[cfg(feature = "watcher")]
    {
        if let Some(w) = e.get_mut_watcher() {
            w.update(d);
        }
    }
}

#[cfg(feature = "cached")]
#[allow(unused_variables)]
pub(crate) fn clear_cache<T: CoreApi + CachedApi<String, bool>>(
    ce: &mut T,
    d: EventData,
) {
    #[cfg(feature = "logging")]
    {
        ce.get_logger().print_mgmt_log(&d);
    }
    ce.get_mut_cache().clear();
}
