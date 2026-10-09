use crate::{
    adapter::{Adapter, Filter},
    convert::{EnforceArgs, TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::{DefaultEffector, EffectKind, Effector},
    emitter::{Event, EventData, EventEmitter},
    error::{ModelError, PolicyError, RequestError},
    get_or_err, get_or_err_with_context,
    management_api::MgmtApi,
    model::{FunctionMap, Model, OperatorFunction},
    rbac::{DefaultRoleManager, RoleManager},
    register_g_function,
    util::{escape_assertion, escape_eval},
    Result,
};

use crate::model::DefaultModel;

#[cfg(any(feature = "logging", feature = "watcher"))]
use crate::emitter::notify_logger_and_watcher;

#[cfg(feature = "watcher")]
use crate::watcher::Watcher;

#[cfg(feature = "logging")]
use crate::{DefaultLogger, Logger};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rhai::{
    def_package,
    packages::{
        ArithmeticPackage, BasicArrayPackage, BasicMapPackage, LogicPackage,
        Package,
    },
    Dynamic, Engine, EvalAltResult, ImmutableString, Scope,
};

def_package! {
    pub CasbinPackage(lib) {
        ArithmeticPackage::init(lib);
        LogicPackage::init(lib);
        BasicArrayPackage::init(lib);
        BasicMapPackage::init(lib);

        lib.set_native_fn("escape_assertion", |s: ImmutableString| {
            Ok(escape_assertion(&s))
        });
    }
}

static CASBIN_PACKAGE: Lazy<CasbinPackage> = Lazy::new(CasbinPackage::new);

use std::{cmp::max, collections::HashMap, sync::Arc};

type EventCallback = fn(&mut Enforcer, EventData);

/// Enforcer is the main interface for authorization enforcement and policy management.
pub struct Enforcer {
    model: Box<dyn Model>,
    adapter: Box<dyn Adapter>,
    fm: FunctionMap,
    eft: Box<dyn Effector>,
    rm_map: HashMap<String, Arc<RwLock<dyn RoleManager>>>,
    enabled: bool,
    auto_save: bool,
    auto_build_role_links: bool,
    #[cfg(feature = "watcher")]
    auto_notify_watcher: bool,
    #[cfg(feature = "watcher")]
    watcher: Option<Box<dyn Watcher>>,
    events: HashMap<Event, Vec<EventCallback>>,
    engine: Engine,
    #[cfg(feature = "logging")]
    logger: Box<dyn Logger>,
}

pub struct EnforceContext {
    pub r_type: String,
    pub p_type: String,
    pub e_type: String,
    pub m_type: String,
}

impl EnforceContext {
    pub fn new(suffix: &str) -> Self {
        Self {
            r_type: format!("r{}", suffix),
            p_type: format!("p{}", suffix),
            e_type: format!("e{}", suffix),
            m_type: format!("m{}", suffix),
        }
    }
    pub fn get_cache_key(&self) -> String {
        format!(
            "EnforceContext{{{}-{}-{}-{}}}",
            self.r_type, self.p_type, self.e_type, self.m_type,
        )
    }
}

impl EventEmitter<Event> for Enforcer {
    fn on(&mut self, e: Event, f: fn(&mut Self, EventData)) {
        self.events.entry(e).or_default().push(f)
    }

    fn off(&mut self, e: Event) {
        self.events.remove(&e);
    }

    fn emit(&mut self, e: Event, d: EventData) {
        if let Some(cbs) = self.events.get(&e) {
            for cb in cbs.clone().iter() {
                cb(self, d.clone())
            }
        }
    }
}

impl Enforcer {
    pub(crate) fn private_enforce(
        &self,
        rvals: &[Dynamic],
    ) -> Result<(bool, Option<Vec<usize>>)> {
        if !self.enabled {
            return Ok((true, None));
        }

        let mut scope: Scope = Scope::new();

        let r_ast = get_or_err!(self, "r", ModelError::R, "request");
        let p_ast = get_or_err!(self, "p", ModelError::P, "policy");
        let m_ast = get_or_err!(self, "m", ModelError::M, "matcher");
        let e_ast = get_or_err!(self, "e", ModelError::E, "effector");

        if r_ast.tokens.len() != rvals.len() {
            return Err(RequestError::UnmatchRequestDefinition(
                r_ast.tokens.len(),
                rvals.len(),
            )
            .into());
        }

        for (rtoken, rval) in r_ast.tokens.iter().zip(rvals.iter()) {
            scope.push_constant_dynamic(rtoken, rval.to_owned());
        }

        let policies = p_ast.get_policy();
        let (policy_len, scope_len) = (policies.len(), scope.len());

        let mut eft_stream =
            self.eft.new_stream(&e_ast.value, max(policy_len, 1));
        let m_ast_compiled = if let Some(default_model) =
            self.model.as_any().downcast_ref::<DefaultModel>()
        {
            default_model.get_compiled_matcher("m").ok_or_else(|| {
                crate::error::Error::ModelError(crate::error::ModelError::M(
                    "Matcher 'm' not compiled".to_string(),
                ))
            })?
        } else {
            // Fallback to original compilation (for other Model implementations)
            &self
                .engine
                .compile_expression(escape_eval(&m_ast.value))
                .map_err(Into::<Box<EvalAltResult>>::into)?
        };

        if policy_len == 0 {
            for token in p_ast.tokens.iter() {
                scope.push_constant(token, String::new());
            }

            let eval_result = self
                .engine
                .eval_ast_with_scope::<bool>(&mut scope, m_ast_compiled)?;
            let eft = if eval_result {
                EffectKind::Allow
            } else {
                EffectKind::Indeterminate
            };

            eft_stream.push_effect(eft);

            return Ok((eft_stream.next(), None));
        }

        for pvals in policies {
            scope.rewind(scope_len);

            if p_ast.tokens.len() != pvals.len() {
                return Err(PolicyError::UnmatchPolicyDefinition(
                    p_ast.tokens.len(),
                    pvals.len(),
                )
                .into());
            }
            for (ptoken, pval) in p_ast.tokens.iter().zip(pvals.iter()) {
                scope.push_constant(ptoken, pval.to_owned());
            }

            let eval_result = self
                .engine
                .eval_ast_with_scope::<bool>(&mut scope, m_ast_compiled)?;
            let eft = match p_ast.tokens.iter().position(|x| x == "p_eft") {
                Some(j) if eval_result => {
                    let p_eft = &pvals[j];
                    if p_eft == "deny" {
                        EffectKind::Deny
                    } else if p_eft == "allow" {
                        EffectKind::Allow
                    } else {
                        EffectKind::Indeterminate
                    }
                }
                None if eval_result => EffectKind::Allow,
                _ => EffectKind::Indeterminate,
            };

            if eft_stream.push_effect(eft) {
                break;
            }
        }

        Ok((eft_stream.next(), {
            #[cfg(feature = "explain")]
            {
                eft_stream.explain()
            }
            #[cfg(not(feature = "explain"))]
            {
                None
            }
        }))
    }

    pub(crate) fn private_enforce_with_context(
        &self,
        ctx: EnforceContext,
        rvals: &[Dynamic],
    ) -> Result<(bool, Option<Vec<usize>>)> {
        if !self.enabled {
            return Ok((true, None));
        }

        let mut scope: Scope = Scope::new();
        let r_ast = get_or_err_with_context!(
            self,
            "r",
            &ctx.r_type,
            ModelError::R,
            "request"
        );
        let p_ast = get_or_err_with_context!(
            self,
            "p",
            &ctx.p_type,
            ModelError::P,
            "policy"
        );
        let m_ast = get_or_err_with_context!(
            self,
            "m",
            &ctx.m_type,
            ModelError::M,
            "matcher"
        );
        let e_ast = get_or_err_with_context!(
            self,
            "e",
            &ctx.e_type,
            ModelError::E,
            "effector"
        );

        if r_ast.tokens.len() != rvals.len() {
            return Err(RequestError::UnmatchRequestDefinition(
                r_ast.tokens.len(),
                rvals.len(),
            )
            .into());
        }

        for (rtoken, rval) in r_ast.tokens.iter().zip(rvals.iter()) {
            scope.push_constant_dynamic(rtoken, rval.to_owned());
        }

        let policies = p_ast.get_policy();
        let (policy_len, scope_len) = (policies.len(), scope.len());

        let mut eft_stream =
            self.eft.new_stream(&e_ast.value, max(policy_len, 1));
        let m_ast_compiled = if let Some(default_model) =
            self.model.as_any().downcast_ref::<DefaultModel>()
        {
            default_model.get_compiled_matcher(&ctx.m_type).ok_or_else(
                || {
                    crate::error::Error::ModelError(
                        crate::error::ModelError::M(format!(
                            "Matcher '{}' not compiled",
                            ctx.m_type
                        )),
                    )
                },
            )?
        } else {
            // Fallback to original compilation (for other Model implementations)
            &self
                .engine
                .compile_expression(escape_eval(&m_ast.value))
                .map_err(Into::<Box<EvalAltResult>>::into)?
        };

        if policy_len == 0 {
            for token in p_ast.tokens.iter() {
                scope.push_constant(token, String::new());
            }

            let eval_result = self
                .engine
                .eval_ast_with_scope::<bool>(&mut scope, m_ast_compiled)?;
            let eft = if eval_result {
                EffectKind::Allow
            } else {
                EffectKind::Indeterminate
            };

            eft_stream.push_effect(eft);

            return Ok((eft_stream.next(), None));
        }

        for pvals in policies {
            scope.rewind(scope_len);

            if p_ast.tokens.len() != pvals.len() {
                return Err(PolicyError::UnmatchPolicyDefinition(
                    p_ast.tokens.len(),
                    pvals.len(),
                )
                .into());
            }
            for (ptoken, pval) in p_ast.tokens.iter().zip(pvals.iter()) {
                scope.push_constant(ptoken, pval.to_owned());
            }

            let eval_result = self
                .engine
                .eval_ast_with_scope::<bool>(&mut scope, m_ast_compiled)?;
            let eft = match p_ast.tokens.iter().position(|x| x == "p_eft") {
                Some(j) if eval_result => {
                    let p_eft = &pvals[j];
                    if p_eft == "deny" {
                        EffectKind::Deny
                    } else if p_eft == "allow" {
                        EffectKind::Allow
                    } else {
                        EffectKind::Indeterminate
                    }
                }
                None if eval_result => EffectKind::Allow,
                _ => EffectKind::Indeterminate,
            };

            if eft_stream.push_effect(eft) {
                break;
            }
        }

        Ok((eft_stream.next(), {
            #[cfg(feature = "explain")]
            {
                eft_stream.explain()
            }
            #[cfg(not(feature = "explain"))]
            {
                None
            }
        }))
    }

    fn register_function(engine: &mut Engine, key: &str, f: OperatorFunction) {
        match f {
            OperatorFunction::Arg0(func) => {
                engine.register_fn(key, func);
            }
            OperatorFunction::Arg1(func) => {
                engine.register_fn(key, func);
            }
            OperatorFunction::Arg2(func) => {
                engine.register_fn(key, func);
            }
            OperatorFunction::Arg3(func) => {
                engine.register_fn(key, func);
            }
            OperatorFunction::Arg4(func) => {
                engine.register_fn(key, func);
            }
            OperatorFunction::Arg5(func) => {
                engine.register_fn(key, func);
            }
            OperatorFunction::Arg6(func) => {
                engine.register_fn(key, func);
            }
        }
    }

    fn init_rm_map(&mut self) {
        self.rm_map.entry("g".to_owned()).or_insert_with(|| {
            Arc::new(RwLock::new(DefaultRoleManager::new(10)))
        });
        if let Some(ast_map) = self.model.get_model().get("g") {
            for ptype in ast_map.keys() {
                self.rm_map.entry(ptype.to_owned()).or_insert_with(|| {
                    Arc::new(RwLock::new(DefaultRoleManager::new(10)))
                });
            }
        }
    }

    pub(crate) fn register_g_functions(&mut self) -> Result<()> {
        self.init_rm_map();
        if let Some(ast_map) = self.model.get_model().get("g") {
            for (fname, ast) in ast_map {
                register_g_function!(self, fname, ast);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl CoreApi for Enforcer {
    #[allow(clippy::box_default)]
    async fn new_raw<M: TryIntoModel, A: TryIntoAdapter>(
        m: M,
        a: A,
    ) -> Result<Self> {
        let model = m.try_into_model().await?;
        let adapter = a.try_into_adapter().await?;
        let fm = FunctionMap::default();
        let eft = Box::new(DefaultEffector);

        let mut engine = Engine::new_raw();

        engine.register_global_module(CASBIN_PACKAGE.as_shared_module());

        for (key, &func) in fm.get_functions() {
            Self::register_function(&mut engine, key, func);
        }

        let mut e = Self {
            model,
            adapter,
            fm,
            eft,
            rm_map: HashMap::new(),
            enabled: true,
            auto_save: true,
            auto_build_role_links: true,
            #[cfg(feature = "watcher")]
            auto_notify_watcher: true,
            #[cfg(feature = "watcher")]
            watcher: None,
            events: HashMap::new(),
            engine,
            #[cfg(feature = "logging")]
            logger: Box::new(DefaultLogger::default()),
        };

        #[cfg(any(feature = "logging", feature = "watcher"))]
        e.on(Event::PolicyChange, notify_logger_and_watcher);

        e.register_g_functions()?;

        // If using DefaultModel, compile matcher expressions
        if let Some(default_model) =
            e.model.as_any_mut().downcast_mut::<DefaultModel>()
        {
            default_model.compile_matchers(&e.engine)?;
        }

        Ok(e)
    }

    #[inline]
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(
        m: M,
        a: A,
    ) -> Result<Self> {
        let mut e = Self::new_raw(m, a).await?;

        // Do not initialize the full policy when using a filtered adapter
        if !e.adapter.is_filtered() {
            e.load_policy().await?;
        }
        Ok(e)
    }

    #[inline]
    fn add_function(&mut self, fname: &str, f: OperatorFunction) {
        self.fm.add_function(fname, f);
        Self::register_function(&mut self.engine, fname, f);
    }

    #[inline]
    fn get_model(&self) -> &dyn Model {
        &*self.model
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut dyn Model {
        &mut *self.model
    }

    #[inline]
    fn get_adapter(&self) -> &dyn Adapter {
        &*self.adapter
    }

    #[inline]
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter {
        &mut *self.adapter
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.watcher = Some(w);
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn get_logger(&self) -> &dyn Logger {
        &*self.logger
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn set_logger(&mut self, l: Box<dyn Logger>) {
        self.logger = l;
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_watcher(&self) -> Option<&dyn Watcher> {
        if let Some(ref watcher) = self.watcher {
            Some(&**watcher)
        } else {
            None
        }
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher> {
        if let Some(ref mut watcher) = self.watcher {
            Some(&mut **watcher)
        } else {
            None
        }
    }

    #[inline]
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>> {
        Arc::clone(&self.rm_map["g"])
    }

    #[inline]
    fn set_role_manager(
        &mut self,
        rm: Arc<RwLock<dyn RoleManager>>,
    ) -> Result<()> {
        self.set_named_role_manager("g", rm)
    }

    #[inline]
    fn get_named_role_manager(
        &self,
        ptype: &str,
    ) -> Option<Arc<RwLock<dyn RoleManager>>> {
        self.rm_map.get(ptype).map(Arc::clone)
    }

    fn set_named_role_manager(
        &mut self,
        ptype: &str,
        rm: Arc<RwLock<dyn RoleManager>>,
    ) -> Result<()> {
        self.rm_map.insert(ptype.to_owned(), rm);
        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        self.register_g_functions()
    }

    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()> {
        self.model = m.try_into_model().await?;

        // If using DefaultModel, recompile matcher expressions
        if let Some(default_model) =
            self.model.as_any_mut().downcast_mut::<DefaultModel>()
        {
            default_model.compile_matchers(&self.engine)?;
        }

        self.register_g_functions()?;
        self.load_policy().await?;
        Ok(())
    }

    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()> {
        self.adapter = a.try_into_adapter().await?;
        self.load_policy().await?;
        Ok(())
    }

    #[inline]
    fn set_effector(&mut self, e: Box<dyn Effector>) {
        self.eft = e;
    }

    /// Enforce decides whether a "subject" can access a "object" with the operation "action",
    /// input parameters are usually: (sub, obj, act).
    ///
    /// # Examples
    /// ```
    /// use casbin::prelude::*;
    /// #[cfg(feature = "runtime-async-std")]
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let mut e = Enforcer::new("examples/basic_model.conf", "examples/basic_policy.csv").await?;
    ///     assert_eq!(true, e.enforce(("alice", "data1", "read"))?);
    ///     Ok(())
    /// }
    ///
    /// #[cfg(feature = "runtime-tokio")]
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let mut e = Enforcer::new("examples/basic_model.conf", "examples/basic_policy.csv").await?;
    ///     assert_eq!(true, e.enforce(("alice", "data1", "read"))?);
    ///
    ///     Ok(())
    /// }
    /// #[cfg(all(not(feature = "runtime-async-std"), not(feature = "runtime-tokio")))]
    /// fn main() {}
    /// ```
    fn enforce<ARGS: EnforceArgs>(&self, rvals: ARGS) -> Result<bool> {
        let rvals = rvals.try_into_vec()?;
        #[allow(unused_variables)]
        let (authorized, indices) = self.private_enforce(&rvals)?;

        #[cfg(feature = "logging")]
        {
            self.logger.print_enforce_log(
                rvals.iter().map(|x| x.to_string()).collect(),
                authorized,
                false,
            );

            #[cfg(feature = "explain")]
            if let Some(indices) = indices {
                let all_rules = get_or_err!(self, "p", ModelError::P, "policy")
                    .get_policy();

                let rules: Vec<String> = indices
                    .into_iter()
                    .filter_map(|y| {
                        all_rules.iter().nth(y).map(|x| x.join(", "))
                    })
                    .collect();

                self.logger.print_explain_log(rules);
            }
        }

        Ok(authorized)
    }
    /// Enforce decides whether a "subject" can access a "object" with the operation "action",
    /// input parameters are usually: (sub, obj, act).
    /// this function will add suffix to each model eg. r2, p2, e2, m2, g2,
    ///
    /// # Examples
    /// ```
    /// use casbin::prelude::*;
    /// use casbin::EnforceContext;
    ///
    /// #[cfg(feature = "runtime-async-std")]
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let mut e = Enforcer::new("examples/multi_section_model.conf", "examples/multi_section_policy.csv").await?;
    ///     assert_eq!(true, e.enforce(("alice", "read", "project1"))?);
    ///     let ctx = EnforceContext::new("2");
    ///     assert_eq!(true, e.enforce_with_context(ctx, ("james", "execute"))?);
    ///     Ok(())
    /// }
    ///
    /// #[cfg(feature = "runtime-tokio")]
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let mut e = Enforcer::new("examples/multi_section_model.conf", "examples/multi_section_policy.csv").await?;
    ///     assert_eq!(true, e.enforce(("alice", "read", "project1"))?);
    ///     let ctx = EnforceContext::new("2");
    ///     assert_eq!(true, e.enforce_with_context(ctx, ("james", "execute"))?);
    ///
    ///     Ok(())
    /// }
    /// #[cfg(all(not(feature = "runtime-async-std"), not(feature = "runtime-tokio")))]
    /// fn main() {}
    /// ```
    fn enforce_with_context<ARGS: EnforceArgs>(
        &self,
        ctx: EnforceContext,
        rvals: ARGS,
    ) -> Result<bool> {
        let rvals = rvals.try_into_vec()?;
        #[allow(unused_variables)]
        let (authorized, indices) =
            self.private_enforce_with_context(ctx, &rvals)?;

        #[cfg(feature = "logging")]
        {
            self.logger.print_enforce_log(
                rvals.iter().map(|x| x.to_string()).collect(),
                authorized,
                false,
            );

            #[cfg(feature = "explain")]
            if let Some(indices) = indices {
                let all_rules = get_or_err!(self, "p", ModelError::P, "policy")
                    .get_policy();

                let rules: Vec<String> = indices
                    .into_iter()
                    .filter_map(|y| {
                        all_rules.iter().nth(y).map(|x| x.join(", "))
                    })
                    .collect();

                self.logger.print_explain_log(rules);
            }
        }

        Ok(authorized)
    }

    fn enforce_mut<ARGS: EnforceArgs>(&mut self, rvals: ARGS) -> Result<bool> {
        self.enforce(rvals)
    }

    #[cfg(feature = "explain")]
    fn enforce_ex<ARGS: EnforceArgs>(
        &self,
        rvals: ARGS,
    ) -> Result<(bool, Vec<Vec<String>>)> {
        let rvals = rvals.try_into_vec()?;
        #[allow(unused_variables)]
        let (authorized, indices) = self.private_enforce(&rvals)?;

        let rules = match indices {
            Some(indices) => {
                let all_rules = get_or_err!(self, "p", ModelError::P, "policy")
                    .get_policy();

                indices
                    .into_iter()
                    .filter_map(|y| all_rules.iter().nth(y).cloned())
                    .collect::<Vec<_>>()
            }
            None => vec![],
        };

        Ok((authorized, rules))
    }

    fn build_role_links(&mut self) -> Result<()> {
        for rm in self.rm_map.values() {
            rm.write().clear();
        }
        self.model.build_role_links(&self.rm_map)?;

        Ok(())
    }

    #[cfg(feature = "incremental")]
    fn build_incremental_role_links(&mut self, d: EventData) -> Result<()> {
        self.model.build_incremental_role_links(&self.rm_map, d)?;

        Ok(())
    }

    async fn load_policy(&mut self) -> Result<()> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut *self.model).await?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        Ok(())
    }

    async fn load_filtered_policy<'a>(&mut self, f: Filter<'a>) -> Result<()> {
        self.model.clear_policy();
        self.adapter
            .load_filtered_policy(&mut *self.model, f)
            .await?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        Ok(())
    }

    #[inline]
    fn is_filtered(&self) -> bool {
        self.adapter.is_filtered()
    }

    #[inline]
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    async fn save_policy(&mut self) -> Result<()> {
        assert!(!self.is_filtered(), "cannot save filtered policy");

        self.adapter.save_policy(&mut *self.model).await?;

        let mut policies = self.get_all_policy();
        let gpolicies = self.get_all_grouping_policy();

        policies.extend(gpolicies);

        #[cfg(any(feature = "logging", feature = "watcher"))]
        self.emit(Event::PolicyChange, EventData::SavePolicy(policies));

        Ok(())
    }

    #[inline]
    async fn clear_policy(&mut self) -> Result<()> {
        if self.auto_save {
            self.adapter.clear_policy().await?;
        }
        self.model.clear_policy();

        #[cfg(any(feature = "logging", feature = "watcher"))]
        self.emit(Event::PolicyChange, EventData::ClearPolicy);

        Ok(())
    }

    #[inline]
    fn enable_enforce(&mut self, enabled: bool) {
        self.enabled = enabled;

        #[cfg(feature = "logging")]
        self.logger.print_status_log(enabled);
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn enable_log(&mut self, enabled: bool) {
        self.logger.enable_log(enabled);
    }

    #[inline]
    fn enable_auto_save(&mut self, auto_save: bool) {
        self.auto_save = auto_save;
    }

    #[inline]
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.auto_build_role_links = auto_build_role_links;
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool) {
        if !auto_notify_watcher {
            self.off(Event::PolicyChange);
        } else {
            self.on(Event::PolicyChange, notify_logger_and_watcher);
        }

        self.auto_notify_watcher = auto_notify_watcher;
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.auto_save
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn has_auto_notify_watcher_enabled(&self) -> bool {
        self.auto_notify_watcher
    }

    #[inline]
    fn has_auto_build_role_links_enabled(&self) -> bool {
        self.auto_build_role_links
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    fn is_send<T: Send>() -> bool {
        true
    }

    fn is_sync<T: Sync>() -> bool {
        true
    }

    #[test]
    fn test_send_sync() {
        assert!(is_send::<Enforcer>());
        assert!(is_sync::<Enforcer>());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_enforcer_swap_adapter_type() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let file = FileAdapter::new("examples/basic_policy.csv");
        let mem = MemoryAdapter::default();
        let mut e = Enforcer::new(m, file).await.unwrap();
        // this should fail since FileAdapter has basically no add_policy
        assert!(e
            .adapter
            .add_policy(
                "p",
                "p",
                vec!["alice".into(), "data".into(), "read".into()]
            )
            .await
            .unwrap());
        e.set_adapter(mem).await.unwrap();
        // this passes since our MemoryAdapter has a working add_policy method
        assert!(e
            .adapter
            .add_policy(
                "p",
                "p",
                vec!["alice".into(), "data".into(), "read".into()]
            )
            .await
            .unwrap())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_key_match_model_in_memory() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();
        assert_eq!(
            true,
            e.enforce(("alice", "/alice_data/resource1", "GET"))
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", "/alice_data/resource1", "POST"))
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", "/alice_data/resource2", "GET"))
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "/alice_data/resource2", "POST"))
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "/bob_data/resource1", "GET")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "/bob_data/resource1", "POST")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "/bob_data/resource2", "GET")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("alice", "/bob_data/resource2", "POST")).unwrap()
        );

        assert_eq!(
            false,
            e.enforce(("bob", "/alice_data/resource1", "GET")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "/alice_data/resource1", "POST")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "/alice_data/resource2", "GET")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "/alice_data/resource2", "POST")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "/bob_data/resource1", "GET")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "/bob_data/resource1", "POST")).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(("bob", "/bob_data/resource2", "GET")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("bob", "/bob_data/resource2", "POST")).unwrap()
        );

        assert_eq!(true, e.enforce(("cathy", "/cathy_data", "GET")).unwrap());
        assert_eq!(true, e.enforce(("cathy", "/cathy_data", "POST")).unwrap());
        assert_eq!(
            false,
            e.enforce(("cathy", "/cathy_data", "DELETE")).unwrap()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_key_match_model_in_memory_deny() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "!some(where (p.eft == deny))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();
        assert_eq!(
            true,
            e.enforce(("alice", "/alice_data/resource2", "POST"))
                .unwrap()
        );
    }

    use crate::RbacApi;
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_in_memory_indeterminate() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_permission_for_user(
            "alice",
            vec!["data1", "invalid"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(false, e.enforce(("alice", "data1", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_rbac_model_in_memory() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_permission_for_user(
            "alice",
            vec!["data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "bob",
            vec!["data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "data2_admin",
            vec!["data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "data2_admin",
            vec!["data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_role_for_user("alice", "data2_admin", None)
            .await
            .unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_not_used_rbac_model_in_memory() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_permission_for_user(
            "alice",
            vec!["data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "bob",
            vec!["data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(feature = "ip")]
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_ip_match_model() {
        let m = DefaultModel::from_file("examples/ipmatch_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/ipmatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(("192.168.2.123", "data1", "read")).unwrap());

        assert!(e.enforce(("10.0.0.5", "data2", "write")).unwrap());

        assert!(!e.enforce(("192.168.2.123", "data1", "write")).unwrap());
        assert!(!e.enforce(("192.168.2.123", "data2", "read")).unwrap());
        assert!(!e.enforce(("192.168.2.123", "data2", "write")).unwrap());

        assert!(!e.enforce(("192.168.0.123", "data1", "read")).unwrap());
        assert!(!e.enforce(("192.168.0.123", "data1", "write")).unwrap());
        assert!(!e.enforce(("192.168.0.123", "data2", "read")).unwrap());
        assert!(!e.enforce(("192.168.0.123", "data2", "write")).unwrap());

        assert!(!e.enforce(("10.0.0.5", "data1", "read")).unwrap());
        assert!(!e.enforce(("10.0.0.5", "data1", "write")).unwrap());
        assert!(!e.enforce(("10.0.0.5", "data2", "read")).unwrap());

        assert!(!e.enforce(("192.168.0.1", "data1", "read")).unwrap());
        assert!(!e.enforce(("192.168.0.1", "data1", "write")).unwrap());
        assert!(!e.enforce(("192.168.0.1", "data2", "read")).unwrap());
        assert!(!e.enforce(("192.168.0.1", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_enable_auto_save() {
        let m = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.enable_auto_save(false);
        e.remove_policy(
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.load_policy().await.unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());

        e.enable_auto_save(true);
        e.remove_policy(
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.load_policy().await.unwrap();
        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data2", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data2", "read")).unwrap());
        assert_eq!(true, e.enforce(("bob", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_role_links() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.enable_auto_build_role_links(false);
        e.build_role_links().unwrap();
        assert_eq!(false, e.enforce(("user501", "data9", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_get_and_set_model() {
        let m1 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        assert_eq!(false, e.enforce(("root", "data1", "read")).unwrap());

        let m2 = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();
        let adapter2 = FileAdapter::new("examples/basic_policy.csv");
        let e2 = Enforcer::new(m2, adapter2).await.unwrap();

        e.model = e2.model;
        assert_eq!(true, e.enforce(("root", "data1", "read")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_get_and_set_adapter_in_mem() {
        let m1 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());

        let m2 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter2 = FileAdapter::new("examples/basic_inverse_policy.csv");
        let e2 = Enforcer::new(m2, adapter2).await.unwrap();

        e.adapter = e2.adapter;
        e.load_policy().await.unwrap();
        assert_eq!(false, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(true, e.enforce(("alice", "data1", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_keymatch_custom_model() {
        use crate::model::key_match;

        let m1 = DefaultModel::from_file("examples/keymatch_custom_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/keymatch_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        e.add_function(
            "keyMatchCustom",
            OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
                let s1_str = s1.to_string();
                let s2_str = s2.to_string();
                key_match(&s1_str, &s2_str).into()
            }),
        );

        assert_eq!(
            true,
            e.enforce(("alice", "/alice_data/123", "GET")).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(("alice", "/alice_data/resource1", "POST"))
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(("bob", "/alice_data/resource2", "GET")).unwrap()
        );

        assert_eq!(
            true,
            e.enforce(("bob", "/bob_data/resource1", "POST")).unwrap()
        );

        assert_eq!(true, e.enforce(("cathy", "/cathy_data", "GET")).unwrap());
        assert_eq!(true, e.enforce(("cathy", "/cathy_data", "POST")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_filtered_file_adapter() {
        let adapter = FileAdapter::new_filtered_adapter(
            "examples/rbac_with_domains_policy.csv",
        );
        let mut e =
            Enforcer::new("examples/rbac_with_domains_model.conf", adapter)
                .await
                .unwrap();

        let filter = Filter {
            p: vec!["", "domain1"],
            g: vec!["", "", "domain1"],
        };

        e.load_filtered_policy(filter).await.unwrap();
        assert_eq!(
            e.enforce(("alice", "domain1", "data1", "read")).unwrap(),
            true
        );
        assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "read")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_grouping_role_managers_are_isolated() {
        use crate::RbacApi;

        let m = DefaultModel::from_str(
            r#"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act
"#,
        )
        .await
        .unwrap();
        let adapter = StringAdapter::new(
            r#"
p, admin, data_group, write
g, alice, admin
g2, report1, data_group
g2, eve, admin
"#,
        );
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.enable_auto_save(false);

        assert!(e.enforce(("alice", "report1", "write")).unwrap());
        assert!(!e.enforce(("eve", "data_group", "write")).unwrap());
        assert!(!e.has_role_for_user("eve", "admin", None));

        e.add_named_grouping_policy(
            "g2",
            vec!["mallory".to_owned(), "admin".to_owned()],
        )
        .await
        .unwrap();

        assert!(!e.enforce(("mallory", "data_group", "write")).unwrap());
        assert!(!e.has_role_for_user("mallory", "admin", None));
        assert!(e
            .get_named_role_manager("g2")
            .unwrap()
            .read()
            .has_link("mallory", "admin", None));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_set_role_manager() {
        let mut e = Enforcer::new(
            "examples/rbac_with_domains_model.conf",
            "examples/rbac_with_domains_policy.csv",
        )
        .await
        .unwrap();

        let new_rm = Arc::new(RwLock::new(DefaultRoleManager::new(10)));

        e.set_role_manager(new_rm).unwrap();

        assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap(),);
        assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
        assert!(e.enforce(("bob", "domain2", "data2", "read")).unwrap());
        assert!(e.enforce(("bob", "domain2", "data2", "write")).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_policy_abac1() {
        use serde::Serialize;

        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub_rule, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act",
        );

        let a = MemoryAdapter::default();

        let mut e = Enforcer::new(m, a).await.unwrap();

        e.add_policy(
            vec!["r.sub.age > 18", "/data1", "read"]
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
        )
        .await
        .unwrap();

        #[derive(Serialize, Hash)]
        pub struct Person<'a> {
            name: &'a str,
            age: u8,
        }

        assert_eq!(
            e.enforce((
                Person {
                    name: "alice",
                    age: 16
                },
                "/data1",
                "read"
            ))
            .unwrap(),
            false
        );
        assert_eq!(
            e.enforce((
                Person {
                    name: "bob",
                    age: 19
                },
                "/data1",
                "read"
            ))
            .unwrap(),
            true
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_policy_abac2() {
        use serde::Serialize;

        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def("g", "g", "_, _");
        m.add_def(
            "m",
            "m",
            "(g(r.sub, p.sub) || eval(p.sub) == true) && r.act == p.act",
        );

        let a = MemoryAdapter::default();

        let mut e = Enforcer::new(m, a).await.unwrap();

        e.add_policy(
            vec![r#""admin""#, "post", "write"]
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
        )
        .await
        .unwrap();

        e.add_policy(
            vec!["r.sub == r.obj.author", "post", "write"]
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
        )
        .await
        .unwrap();

        e.add_grouping_policy(
            vec!["alice", r#""admin""#]
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
        )
        .await
        .unwrap();

        #[derive(Serialize, Hash)]
        pub struct Post<'a> {
            author: &'a str,
        }

        assert_eq!(
            e.enforce(("alice", Post { author: "bob" }, "write"))
                .unwrap(),
            true
        );

        assert_eq!(
            e.enforce(("bob", Post { author: "bob" }, "write")).unwrap(),
            true
        );
    }

    #[cfg(feature = "explain")]
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_enforce_ex() {
        use crate::adapter;

        let model = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = adapter::FileAdapter::new("examples/basic_policy.csv");

        let e = Enforcer::new(model, adapter).await.unwrap();

        assert_eq!(
            e.enforce_ex(("alice", "data1", "read")).unwrap(),
            (
                true,
                vec![vec![
                    "alice".to_string(),
                    "data1".to_string(),
                    "read".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("alice", "data1", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("alice", "data2", "read")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("alice", "data2", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data1", "read")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data1", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data2", "read")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data2", "write")).unwrap(),
            (
                true,
                vec![vec![
                    "bob".to_string(),
                    "data2".to_string(),
                    "write".to_string()
                ]]
            )
        );

        let e = Enforcer::new(
            "examples/rbac_model.conf",
            "examples/rbac_policy.csv",
        )
        .await
        .unwrap();

        assert_eq!(
            e.enforce_ex(("alice", "data1", "read")).unwrap(),
            (
                true,
                vec![vec![
                    "alice".to_string(),
                    "data1".to_string(),
                    "read".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("alice", "data1", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("alice", "data2", "read")).unwrap(),
            (
                true,
                vec![vec![
                    "data2_admin".to_string(),
                    "data2".to_string(),
                    "read".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("alice", "data2", "write")).unwrap(),
            (
                true,
                vec![vec![
                    "data2_admin".to_string(),
                    "data2".to_string(),
                    "write".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("bob", "data1", "read")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data1", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data2", "read")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data2", "write")).unwrap(),
            (
                true,
                vec![vec![
                    "bob".to_string(),
                    "data2".to_string(),
                    "write".to_string()
                ]]
            )
        );

        let e = Enforcer::new(
            "examples/priority_model.conf",
            "examples/priority_policy.csv",
        )
        .await
        .unwrap();

        assert_eq!(
            e.enforce_ex(("alice", "data1", "read")).unwrap(),
            (
                true,
                vec![vec![
                    "alice".to_string(),
                    "data1".to_string(),
                    "read".to_string(),
                    "allow".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("alice", "data1", "write")).unwrap(),
            (
                false,
                vec![vec![
                    "data1_deny_group".to_string(),
                    "data1".to_string(),
                    "write".to_string(),
                    "deny".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("alice", "data2", "read")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("alice", "data2", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data1", "write")).unwrap(),
            (false, vec![])
        );
        assert_eq!(
            e.enforce_ex(("bob", "data2", "read")).unwrap(),
            (
                true,
                vec![vec![
                    "data2_allow_group".to_string(),
                    "data2".to_string(),
                    "read".to_string(),
                    "allow".to_string()
                ]]
            )
        );
        assert_eq!(
            e.enforce_ex(("bob", "data2", "write")).unwrap(),
            (
                false,
                vec![vec![
                    "bob".to_string(),
                    "data2".to_string(),
                    "write".to_string(),
                    "deny".to_string()
                ]]
            )
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_custom_function_with_dynamic_types() {
        use crate::prelude::*;

        let m = DefaultModel::from_str(
            r#"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"#,
        )
        .await
        .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        // Test 1: Custom function that takes integer arguments
        e.add_function(
            "greaterThan",
            OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
                // Dynamic can hold integers - extract and compare
                let a_int = a.as_int().unwrap_or(0);
                let b_int = b.as_int().unwrap_or(0);
                (a_int > b_int).into()
            }),
        );

        // Test 2: Custom function that works with booleans
        e.add_function(
            "customAnd",
            OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
                // Dynamic can hold booleans - extract and perform logic
                let a_bool = a.as_bool().unwrap_or(false);
                let b_bool = b.as_bool().unwrap_or(false);
                (a_bool && b_bool).into()
            }),
        );

        // Test 3: Custom function that works with strings
        e.add_function(
            "stringContains",
            OperatorFunction::Arg2(|haystack: Dynamic, needle: Dynamic| {
                // Dynamic can hold strings - convert and check
                let haystack_str = haystack.to_string();
                let needle_str = needle.to_string();
                haystack_str.contains(&needle_str).into()
            }),
        );

        // Test 4: Custom function with 3 arguments
        e.add_function(
            "between",
            OperatorFunction::Arg3(
                |val: Dynamic, min: Dynamic, max: Dynamic| {
                    // Check if val is between min and max (inclusive)
                    let val_int = val.as_int().unwrap_or(0);
                    let min_int = min.as_int().unwrap_or(0);
                    let max_int = max.as_int().unwrap_or(0);
                    (val_int >= min_int && val_int <= max_int).into()
                },
            ),
        );

        // Verify that custom functions are registered without errors
        // In real usage, these would be called from policy matchers

        // Test basic enforcement still works with Dynamic-based functions
        e.add_policy(vec![
            "alice".to_owned(),
            "data1".to_owned(),
            "read".to_owned(),
        ])
        .await
        .unwrap();

        assert_eq!(true, e.enforce(("alice", "data1", "read")).unwrap());
        assert_eq!(false, e.enforce(("alice", "data1", "write")).unwrap());
        assert_eq!(false, e.enforce(("bob", "data1", "read")).unwrap());
    }
}
