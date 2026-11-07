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
    error::{AdapterError, ModelError},
    model::Model,
    util::parse_csv_line,
    Result,
};

#[cfg(feature = "runtime-async-std")]
use async_std::{
    fs::File as file, io::prelude::*, io::BufReader as ioBufReader,
    path::Path as ioPath, prelude::*,
};

#[cfg(feature = "runtime-tokio")]
use std::path::Path as ioPath;
#[cfg(feature = "runtime-tokio")]
use tokio::{
    fs::File as file,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as ioBufReader},
};

use async_trait::async_trait;
use std::fmt::Write;

pub struct FileAdapter<P> {
    file_path: P,
    is_filtered: bool,
}

type LoadPolicyFileHandler = fn(String, &mut dyn Model);
type LoadFilteredPolicyFileHandler<'a> =
    fn(String, &mut dyn Model, f: &Filter<'a>) -> bool;

impl<P> FileAdapter<P>
where
    P: AsRef<ioPath> + Send + Sync,
{
    pub fn new(p: P) -> FileAdapter<P> {
        FileAdapter {
            file_path: p,
            is_filtered: false,
        }
    }

    pub fn new_filtered_adapter(p: P) -> FileAdapter<P> {
        FileAdapter {
            file_path: p,
            is_filtered: true,
        }
    }

    async fn load_policy_file(
        &mut self,
        m: &mut dyn Model,
        handler: LoadPolicyFileHandler,
    ) -> Result<()> {
        let f = file::open(&self.file_path).await?;
        let mut lines = ioBufReader::new(f).lines();
        #[cfg(feature = "runtime-async-std")]
        while let Some(line) = lines.next().await {
            handler(line?, m)
        }

        #[cfg(feature = "runtime-tokio")]
        while let Some(line) = lines.next_line().await? {
            handler(line, m)
        }

        Ok(())
    }

    async fn load_filtered_policy_file<'a>(
        &self,
        m: &mut dyn Model,
        filter: Filter<'a>,
        handler: LoadFilteredPolicyFileHandler<'a>,
    ) -> Result<bool> {
        let f = file::open(&self.file_path).await?;
        let mut lines = ioBufReader::new(f).lines();

        let mut is_filtered = false;
        #[cfg(feature = "runtime-async-std")]
        while let Some(line) = lines.next().await {
            if handler(line?, m, &filter) {
                is_filtered = true;
            }
        }

        #[cfg(feature = "runtime-tokio")]
        while let Some(line) = lines.next_line().await? {
            if handler(line, m, &filter) {
                is_filtered = true;
            }
        }

        Ok(is_filtered)
    }

    async fn save_policy_file(&self, text: String) -> Result<()> {
        let mut file = file::create(&self.file_path).await?;
        file.write_all(text.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl<P> Adapter for FileAdapter<P>
where
    P: AsRef<ioPath> + Send + Sync,
{
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.is_filtered = false;
        self.load_policy_file(m, load_policy_line).await?;
        Ok(())
    }

    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<()> {
        self.is_filtered = self
            .load_filtered_policy_file(m, f, load_filtered_policy_line)
            .await?;

        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        if self.file_path.as_ref().as_os_str().is_empty() {
            return Err(std::io::Error::other(
                "save policy failed, file path is empty",
            )
            .into());
        }

        let mut policies = String::new();
        let ast_map = m.get_model().get("p").ok_or_else(|| {
            ModelError::P("Missing policy definition in conf file".to_owned())
        })?;

        for (ptype, ast) in ast_map {
            for rule in ast.get_policy() {
                writeln!(policies, "{}, {}", ptype, rule.join(", "))
                    .map_err(|e| AdapterError(e.into()))?;
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                for rule in ast.get_policy() {
                    writeln!(policies, "{}, {}", ptype, rule.join(", "))
                        .map_err(|e| AdapterError(e.into()))?;
                }
            }
        }

        // Remove trailing newline to match the original file format
        if policies.ends_with('\n') {
            policies.pop();
        }

        self.save_policy_file(policies).await?;
        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.save_policy_file(String::new()).await?;
        Ok(())
    }

    async fn add_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn remove_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<Vec<String>>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<String>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
}

fn load_policy_line(line: String, m: &mut dyn Model) {
    if line.is_empty() || line.starts_with('#') {
        return;
    }

    if let Some(tokens) = parse_csv_line(line) {
        let key = &tokens[0];

        if let Some(ref sec) = key.chars().next().map(|x| x.to_string()) {
            if let Some(ast_map) = m.get_mut_model().get_mut(sec) {
                if let Some(ast) = ast_map.get_mut(key) {
                    ast.policy.insert(tokens[1..].to_vec());
                }
            }
        }
    }
}

fn load_filtered_policy_line(
    line: String,
    m: &mut dyn Model,
    f: &Filter<'_>,
) -> bool {
    if line.is_empty() || line.starts_with('#') {
        return false;
    }

    if let Some(tokens) = parse_csv_line(line) {
        let key = &tokens[0];

        let mut is_filtered = false;
        if let Some(ref sec) = key.chars().next().map(|x| x.to_string()) {
            if sec == "p" {
                for (i, rule) in f.p.iter().enumerate() {
                    if !rule.is_empty() && rule != &tokens[i + 1] {
                        is_filtered = true;
                    }
                }
            }
            if sec == "g" {
                for (i, rule) in f.g.iter().enumerate() {
                    if !rule.is_empty() && rule != &tokens[i + 1] {
                        is_filtered = true;
                    }
                }
            }
            if !is_filtered {
                if let Some(ast_map) = m.get_mut_model().get_mut(sec) {
                    if let Some(ast) = ast_map.get_mut(key) {
                        ast.policy.insert(tokens[1..].to_vec());
                    }
                }
            }
        }

        is_filtered
    } else {
        false
    }
}
