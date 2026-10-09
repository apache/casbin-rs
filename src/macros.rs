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
        let count = $ast.value.matches('_').count();

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
