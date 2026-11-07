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

use crate::Result;

pub type MatchingFn = fn(&str, &str) -> bool;

pub trait RoleManager: Send + Sync {
    fn clear(&mut self);
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>);
    fn matching_fn(
        &mut self,
        role_matching_fn: Option<MatchingFn>,
        domain_matching_fn: Option<MatchingFn>,
    );
    fn delete_link(
        &mut self,
        name1: &str,
        name2: &str,
        domain: Option<&str>,
    ) -> Result<()>;
    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> bool;
    fn get_roles(&self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String>;
}
