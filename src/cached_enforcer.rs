use crate::{
    adapter::{Adapter, Filter},
    cache::{Cache, DefaultCache},
    cached_api::CachedApi,
    convert::{EnforceArgs, TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::Effector,
    emitter::{clear_cache, Event, EventData, EventEmitter},
    enforcer::EnforceContext,
    enforcer::Enforcer,
    model::{Model, OperatorFunction},
    rbac::RoleManager,
    Result,
};

#[cfg(any(feature = "logging", feature = "watcher"))]
use crate::emitter::notify_logger_and_watcher;

#[cfg(feature = "watcher")]
use crate::watcher::Watcher;

#[cfg(feature = "logging")]
use crate::logger::Logger;

#[cfg(feature = "explain")]
use crate::{error::ModelError, get_or_err};

use async_trait::async_trait;
use parking_lot::RwLock;
use rhai::Dynamic;

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::Arc,
};

type EventCallback = fn(&mut CachedEnforcer, EventData);

pub struct CachedEnforcer {
    enforcer: Enforcer,
    cache: Box<dyn Cache<u64, bool>>,
    events: HashMap<Event, Vec<EventCallback>>,
}

impl EventEmitter<Event> for CachedEnforcer {
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

impl CachedEnforcer {
    #[inline]
    fn invalidate_cache(&self) {
        self.cache.clear();
    }

    pub(crate) fn private_enforce(
        &self,
        rvals: &[Dynamic],
        cache_key: u64,
    ) -> Result<(bool, bool, Option<Vec<usize>>)> {
        if !self.enforcer.is_enabled() {
            let (authorized, indices) = self.enforcer.private_enforce(rvals)?;
            return Ok((authorized, false, indices));
        }

        Ok(if let Some(authorized) = self.cache.get(&cache_key) {
            (authorized, true, None)
        } else {
            let (authorized, indices) = self.enforcer.private_enforce(rvals)?;
            self.cache.set(cache_key, authorized);
            (authorized, false, indices)
        })
    }
    pub(crate) fn private_enforce_with_context(
        &self,
        ctx: EnforceContext,
        rvals: &[Dynamic],
        cache_key: u64,
    ) -> Result<(bool, bool, Option<Vec<usize>>)> {
        if !self.enforcer.is_enabled() {
            let (authorized, indices) =
                self.enforcer.private_enforce_with_context(ctx, rvals)?;
            return Ok((authorized, false, indices));
        }

        let cache_key = {
            let mut hasher = DefaultHasher::new();
            cache_key.hash(&mut hasher);
            ctx.get_cache_key().hash(&mut hasher);
            hasher.finish()
        };

        Ok(if let Some(authorized) = self.cache.get(&cache_key) {
            (authorized, true, None)
        } else {
            let (authorized, indices) =
                self.enforcer.private_enforce_with_context(ctx, rvals)?;
            self.cache.set(cache_key, authorized);
            (authorized, false, indices)
        })
    }
}

#[async_trait]
impl CoreApi for CachedEnforcer {
    async fn new_raw<M: TryIntoModel, A: TryIntoAdapter>(
        m: M,
        a: A,
    ) -> Result<CachedEnforcer> {
        let enforcer = Enforcer::new_raw(m, a).await?;
        let cache = Box::new(DefaultCache::new(200));

        let mut cached_enforcer = CachedEnforcer {
            enforcer,
            cache,
            events: HashMap::new(),
        };

        cached_enforcer.on(Event::ClearCache, clear_cache);

        #[cfg(any(feature = "logging", feature = "watcher"))]
        cached_enforcer.on(Event::PolicyChange, notify_logger_and_watcher);

        Ok(cached_enforcer)
    }

    #[inline]
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(
        m: M,
        a: A,
    ) -> Result<CachedEnforcer> {
        let mut cached_enforcer = Self::new_raw(m, a).await?;
        cached_enforcer.load_policy().await?;
        Ok(cached_enforcer)
    }

    #[inline]
    fn add_function(&mut self, fname: &str, f: OperatorFunction) {
        self.enforcer.add_function(fname, f);
        self.invalidate_cache();
    }

    #[inline]
    fn get_model(&self) -> &dyn Model {
        self.enforcer.get_model()
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut dyn Model {
        self.invalidate_cache();
        self.enforcer.get_mut_model()
    }

    #[inline]
    fn get_adapter(&self) -> &dyn Adapter {
        self.enforcer.get_adapter()
    }

    #[inline]
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter {
        self.enforcer.get_mut_adapter()
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.enforcer.set_watcher(w);
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_watcher(&self) -> Option<&dyn Watcher> {
        self.enforcer.get_watcher()
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher> {
        self.enforcer.get_mut_watcher()
    }
    #[inline]
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>> {
        self.enforcer.get_role_manager()
    }

    #[inline]
    fn set_role_manager(
        &mut self,
        rm: Arc<RwLock<dyn RoleManager>>,
    ) -> Result<()> {
        let res = self.enforcer.set_role_manager(rm);
        self.invalidate_cache();
        res
    }

    #[inline]
    fn get_named_role_manager(
        &self,
        ptype: &str,
    ) -> Option<Arc<RwLock<dyn RoleManager>>> {
        self.enforcer.get_named_role_manager(ptype)
    }

    #[inline]
    fn set_named_role_manager(
        &mut self,
        ptype: &str,
        rm: Arc<RwLock<dyn RoleManager>>,
    ) -> Result<()> {
        let res = self.enforcer.set_named_role_manager(ptype, rm);
        self.invalidate_cache();
        res
    }

    #[inline]
    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()> {
        let res = self.enforcer.set_model(m).await;
        self.invalidate_cache();
        res
    }

    #[inline]
    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()> {
        let res = self.enforcer.set_adapter(a).await;
        self.invalidate_cache();
        res
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn get_logger(&self) -> &dyn Logger {
        self.enforcer.get_logger()
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn set_logger(&mut self, l: Box<dyn Logger>) {
        self.enforcer.set_logger(l);
    }

    #[inline]
    fn set_effector(&mut self, e: Box<dyn Effector>) {
        self.enforcer.set_effector(e);
        self.invalidate_cache();
    }

    fn enforce<ARGS: EnforceArgs>(&self, rvals: ARGS) -> Result<bool> {
        let cache_key = rvals.cache_key();

        #[cfg(not(feature = "logging"))]
        if let Some(authorized) = self.cache.get(&cache_key) {
            return Ok(authorized);
        }

        let rvals = rvals.try_into_vec()?;
        #[allow(unused_variables)]
        let (authorized, cached, indices) =
            self.private_enforce(&rvals, cache_key)?;

        #[cfg(feature = "logging")]
        {
            self.enforcer.get_logger().print_enforce_log(
                rvals.iter().map(|x| x.to_string()).collect(),
                authorized,
                cached,
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

                self.enforcer.get_logger().print_explain_log(rules);
            }
        }

        Ok(authorized)
    }

    fn enforce_with_context<ARGS: EnforceArgs>(
        &self,
        ctx: EnforceContext,
        rvals: ARGS,
    ) -> Result<bool> {
        let cache_key = rvals.cache_key();

        #[cfg(not(feature = "logging"))]
        if let Some(authorized) = self.cache.get(&cache_key) {
            return Ok(authorized);
        }

        let rvals = rvals.try_into_vec()?;
        #[allow(unused_variables)]
        let (authorized, cached, indices) =
            self.private_enforce_with_context(ctx, &rvals, cache_key)?;

        #[cfg(feature = "logging")]
        {
            self.enforcer.get_logger().print_enforce_log(
                rvals.iter().map(|x| x.to_string()).collect(),
                authorized,
                cached,
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

                self.enforcer.get_logger().print_explain_log(rules);
            }
        }

        Ok(authorized)
    }

    #[inline]
    fn enforce_mut<ARGS: EnforceArgs>(&mut self, rvals: ARGS) -> Result<bool> {
        self.enforce(rvals)
    }

    #[cfg(feature = "explain")]
    fn enforce_ex<ARGS: EnforceArgs>(
        &self,
        rvals: ARGS,
    ) -> Result<(bool, Vec<Vec<String>>)> {
        let cache_key = rvals.cache_key();
        let rvals = rvals.try_into_vec()?;
        #[allow(unused_variables)]
        let (authorized, cached, indices) =
            self.private_enforce(&rvals, cache_key)?;

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

    #[inline]
    fn build_role_links(&mut self) -> Result<()> {
        let res = self.enforcer.build_role_links();
        self.invalidate_cache();
        res
    }

    #[cfg(feature = "incremental")]
    #[inline]
    fn build_incremental_role_links(&mut self, d: EventData) -> Result<()> {
        let res = self.enforcer.build_incremental_role_links(d);
        self.invalidate_cache();
        res
    }

    #[inline]
    async fn load_policy(&mut self) -> Result<()> {
        let res = self.enforcer.load_policy().await;
        self.invalidate_cache();
        res
    }

    #[inline]
    async fn load_filtered_policy<'a>(&mut self, f: Filter<'a>) -> Result<()> {
        let res = self.enforcer.load_filtered_policy(f).await;
        self.invalidate_cache();
        res
    }

    #[inline]
    fn is_filtered(&self) -> bool {
        self.enforcer.is_filtered()
    }

    #[inline]
    fn is_enabled(&self) -> bool {
        self.enforcer.is_enabled()
    }

    #[inline]
    async fn save_policy(&mut self) -> Result<()> {
        self.enforcer.save_policy().await
    }

    #[inline]
    async fn clear_policy(&mut self) -> Result<()> {
        let res = self.enforcer.clear_policy().await;
        self.invalidate_cache();
        res
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn enable_log(&mut self, enabled: bool) {
        self.enforcer.enable_log(enabled);
    }

    #[inline]
    fn enable_enforce(&mut self, enabled: bool) {
        self.enforcer.enable_enforce(enabled);
        self.invalidate_cache();
    }

    #[inline]
    fn enable_auto_save(&mut self, auto_save: bool) {
        self.enforcer.enable_auto_save(auto_save);
    }

    #[inline]
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.enforcer
            .enable_auto_build_role_links(auto_build_role_links);
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool) {
        self.enforcer
            .enable_auto_notify_watcher(auto_notify_watcher);
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.enforcer.has_auto_save_enabled()
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn has_auto_notify_watcher_enabled(&self) -> bool {
        self.enforcer.has_auto_notify_watcher_enabled()
    }

    #[inline]
    fn has_auto_build_role_links_enabled(&self) -> bool {
        self.enforcer.has_auto_build_role_links_enabled()
    }
}

impl CachedApi<u64, bool> for CachedEnforcer {
    fn get_mut_cache(&mut self) -> &mut dyn Cache<u64, bool> {
        &mut *self.cache
    }

    fn set_cache(&mut self, cache: Box<dyn Cache<u64, bool>>) {
        self.cache = cache;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_send<T: Send>() -> bool {
        true
    }

    fn is_sync<T: Sync>() -> bool {
        true
    }

    #[test]
    fn test_send_sync() {
        assert!(is_send::<CachedEnforcer>());
        assert!(is_sync::<CachedEnforcer>());
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
    async fn test_cache_invalidated_on_lifecycle_changes() {
        use crate::{FileAdapter, MemoryAdapter};

        let m = "examples/basic_model.conf";
        let p = "examples/basic_policy.csv";

        let mut e = CachedEnforcer::new(m, p).await.unwrap();
        assert!(e.enforce(("alice", "data1", "read")).unwrap());
        e.enable_auto_save(false);
        e.clear_policy().await.unwrap();
        assert!(!e.enforce(("alice", "data1", "read")).unwrap());

        let mut e = CachedEnforcer::new(m, p).await.unwrap();
        assert!(e.enforce(("alice", "data1", "read")).unwrap());
        e.set_adapter(MemoryAdapter::default()).await.unwrap();
        assert!(!e.enforce(("alice", "data1", "read")).unwrap());

        let mut e = CachedEnforcer::new(m, p).await.unwrap();
        assert!(e.enforce(("alice", "data1", "read")).unwrap());
        e.get_mut_model().clear_policy();
        assert!(!e.enforce(("alice", "data1", "read")).unwrap());
        e.set_adapter(FileAdapter::new(p)).await.unwrap();
        assert!(e.enforce(("alice", "data1", "read")).unwrap());

        let mut e = CachedEnforcer::new(m, p).await.unwrap();
        e.enable_enforce(false);
        assert!(e.enforce(("bob", "data1", "read")).unwrap());
        e.enable_enforce(true);
        assert!(!e.enforce(("bob", "data1", "read")).unwrap());
        e.enable_enforce(false);
        assert!(e.enforce(("bob", "data1", "read")).unwrap());
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
    async fn test_cache_key_includes_enforce_context() {
        use crate::{DefaultModel, EnforceContext, StringAdapter};

        let m = DefaultModel::from_str(
            r#"
[request_definition]
r = sub, act
r2 = sub, act

[policy_definition]
p = sub, act
p2 = sub, act

[policy_effect]
e = some(where (p.eft == allow))
e2 = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.act == p.act
m2 = r2.sub == p2.sub && r2.act == p2.act
"#,
        )
        .await
        .unwrap();
        let a = StringAdapter::new("p, alice, read");

        let e = CachedEnforcer::new(m, a).await.unwrap();
        assert!(e
            .enforce_with_context(EnforceContext::new(""), ("alice", "read"))
            .unwrap());
        assert!(!e
            .enforce_with_context(EnforceContext::new("2"), ("alice", "read"))
            .unwrap());
    }
}
