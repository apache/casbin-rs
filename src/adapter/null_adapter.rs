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

pub struct NullAdapter;

#[async_trait]
impl Adapter for NullAdapter {
    async fn load_policy(&mut self, _m: &mut dyn Model) -> Result<()> {
        Ok(())
    }

    async fn load_filtered_policy<'a>(
        &mut self,
        _m: &mut dyn Model,
        _f: Filter<'a>,
    ) -> Result<()> {
        Ok(())
    }

    async fn save_policy(&mut self, _m: &mut dyn Model) -> Result<()> {
        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        Ok(())
    }

    async fn add_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    fn is_filtered(&self) -> bool {
        false
    }
}
