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

use async_trait::async_trait;

pub mod memory_adapter;
pub mod null_adapter;
pub mod string_adapter;

#[cfg(not(target_arch = "wasm32"))]
pub mod file_adapter;

pub use memory_adapter::MemoryAdapter;
pub use null_adapter::NullAdapter;
pub use string_adapter::StringAdapter;

#[cfg(not(target_arch = "wasm32"))]
pub use file_adapter::FileAdapter;

use crate::{model::Model, Result};

#[derive(Clone)]
pub struct Filter<'a> {
    pub p: Vec<&'a str>,
    pub g: Vec<&'a str>,
}

#[async_trait]
pub trait Adapter: Send + Sync {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()>;
    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<()>;
    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()>;
    async fn clear_policy(&mut self) -> Result<()>;
    fn is_filtered(&self) -> bool;
    async fn add_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
}
