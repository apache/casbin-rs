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

use slog::info;
use slog::Logger as SLogger;

use crate::emitter::EventData;

mod default_logger;

pub use default_logger::DefaultLogger;

pub trait Logger: Send + Sync {
    fn enable_log(&mut self, enabled: bool);
    fn is_enabled(&self) -> bool;
    fn print_enforce_log(
        &self,
        rvals: Vec<String>,
        authorized: bool,
        cached: bool,
    );
    fn print_mgmt_log(&self, d: &EventData);
    #[cfg(feature = "explain")]
    fn print_explain_log(&self, rules: Vec<String>);
    fn print_status_log(&self, enabled: bool);
}

impl Logger for SLogger {
    fn enable_log(&mut self, _enabled: bool) {}

    fn is_enabled(&self) -> bool {
        true
    }

    fn print_enforce_log(
        &self,
        rvals: Vec<String>,
        authorized: bool,
        cached: bool,
    ) {
        info!(self, "Enforce Request"; "Request" => rvals.join(","), "Cached" => cached, "Response" => authorized);
    }

    fn print_mgmt_log(&self, e: &EventData) {
        info!(self, "Policy Management"; "Event" => e.to_string());
    }

    #[cfg(feature = "explain")]
    fn print_explain_log(&self, rules: Vec<String>) {
        info!(self, "Hitted Policies"; "Explain" => rules.join(","));
    }

    fn print_status_log(&self, enabled: bool) {
        info!(self, "Status"; "Enabled" => enabled);
    }
}
