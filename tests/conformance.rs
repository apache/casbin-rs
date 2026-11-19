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

#![cfg(all(
    feature = "explain",
    feature = "runtime-tokio",
    not(target_arch = "wasm32")
))]

use casbin::prelude::*;
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct ConformanceCase {
    model: String,
    policy: String,
    tests: Vec<ConformanceTest>,
}

#[derive(Deserialize)]
struct ConformanceTest {
    request: Vec<String>,
    allow: bool,
    explain: Vec<String>,
}

async fn run_case(dir: PathBuf, file: PathBuf) -> Vec<String> {
    let name = file.file_name().unwrap().to_string_lossy().to_string();
    let case: ConformanceCase =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    let model =
        DefaultModel::from_file(dir.join("data").join(&case.model)).await;
    let e = match model {
        Ok(model) => {
            Enforcer::new(
                model,
                FileAdapter::new(dir.join("data").join(&case.policy)),
            )
            .await
        }
        Err(err) => Err(err),
    };
    let e = match e {
        Ok(e) => e,
        Err(err) => return vec![format!("{}: {}", name, err)],
    };

    let mut failures = Vec::new();
    for test in case.tests {
        match e.enforce_ex(test.request.clone()) {
            Ok((allow, rules)) => {
                let explain = rules.into_iter().next().unwrap_or_default();
                if allow != test.allow || explain != test.explain {
                    failures.push(format!(
                        "{} {:?}: got ({}, {:?}), want ({}, {:?})",
                        name,
                        test.request,
                        allow,
                        explain,
                        test.allow,
                        test.explain
                    ));
                }
            }
            Err(err) => {
                failures.push(format!("{} {:?}: {}", name, test.request, err))
            }
        }
    }
    failures
}

#[tokio::test]
async fn test_conformance() {
    let dir = match std::env::var("CASBIN_CONFORMANCE_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => return,
    };

    let mut files: Vec<_> = fs::read_dir(dir.join("cases"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no conformance cases found in {:?}", dir);

    let mut failures = Vec::new();
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        match tokio::spawn(run_case(dir.clone(), file)).await {
            Ok(case_failures) => failures.extend(case_failures),
            Err(err) => failures.push(format!("{}: {}", name, err)),
        }
    }

    assert!(
        failures.is_empty(),
        "{} conformance failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
