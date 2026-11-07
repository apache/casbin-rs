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

#[macro_export]
macro_rules! get_or_err {
    ($this:ident, $key:expr, $err:expr, $msg:expr) => {{
        $this
            .get_model()
            .get_model()
            .get($key)
            .ok_or_else(|| {
                $crate::error::Error::from($err(format!(
                    "Missing {} definition in conf file",
                    $msg
                )))
            })?
            .get($key)
            .ok_or_else(|| {
                $crate::error::Error::from($err(format!(
                    "Missing {} section in conf file",
                    $msg
                )))
            })?
    }};
}

#[macro_export]
macro_rules! get_or_err_with_context {
    ($this:ident, $key:expr, $ctx:expr, $err:expr, $msg:expr) => {{
        $this
            .get_model()
            .get_model()
            .get($key)
            .ok_or_else(|| {
                $crate::error::Error::from($err(format!(
                    "Missing {} definition in conf file",
                    $msg
                )))
            })?
            .get($ctx)
            .ok_or_else(|| {
                $crate::error::Error::from($err(format!(
                    "Missing {} section in conf file",
                    $msg
                )))
            })?
    }};
}

#[macro_export]
macro_rules! register_g_function {
    ($enforcer:ident, $fname:ident, $ast:ident) => {{
        let rm = Arc::clone(&$enforcer.rm_map[$fname]);
        let count = $ast.role_token_count();

        if count == 2 {
            $enforcer.engine.register_fn(
                $fname,
                move |arg1: ImmutableString, arg2: ImmutableString| {
                    rm.read().has_link(&arg1, &arg2, None)
                },
            );
        } else if count == 3 {
            $enforcer.engine.register_fn(
                $fname,
                move |arg1: ImmutableString,
                      arg2: ImmutableString,
                      arg3: ImmutableString| {
                    rm.read().has_link(&arg1, &arg2, Some(&arg3))
                },
            );
        } else {
            return Err(ModelError::P(
                r#"the number of "_" in role definition should be at least 2"#
                    .to_owned(),
            )
            .into());
        }
    }};
}

#[macro_export]
macro_rules! push_index_if_explain {
    ($this:ident) => {{
        #[cfg(feature = "explain")]
        if $this.cap > 0 {
            $this.expl.push($this.idx);
        }
    }};
}
