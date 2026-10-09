use crate::{
    enforcer::EnforceContext, model::OperatorFunction, Adapter, Effector,
    EnforceArgs, Event, EventEmitter, Filter, Model, Result, RoleManager,
    TryIntoAdapter, TryIntoModel,
};

#[cfg(feature = "watcher")]
use crate::Watcher;

#[cfg(feature = "logging")]
use crate::Logger;

#[cfg(feature = "incremental")]
use crate::emitter::EventData;

use async_trait::async_trait;
use parking_lot::RwLock;

use std::sync::Arc;

#[async_trait]
pub trait CoreApi: Send + Sync {
    async fn new_raw<M: TryIntoModel, A: TryIntoAdapter>(
        m: M,
        a: A,
    ) -> Result<Self>
    where
        Self: Sized;
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(
        m: M,
        a: A,
    ) -> Result<Self>
    where
        Self: Sized;
    fn add_function(&mut self, fname: &str, f: OperatorFunction);
    fn get_model(&self) -> &dyn Model;
    fn get_mut_model(&mut self) -> &mut dyn Model;
    fn get_adapter(&self) -> &dyn Adapter;
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter;
    #[cfg(feature = "watcher")]
    fn set_watcher(&mut self, w: Box<dyn Watcher>);
    #[cfg(feature = "watcher")]
    fn get_watcher(&self) -> Option<&dyn Watcher>;
    #[cfg(feature = "watcher")]
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher>;
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>>;
    fn set_role_manager(
        &mut self,
        rm: Arc<RwLock<dyn RoleManager>>,
    ) -> Result<()>;
    fn get_named_role_manager(
        &self,
        ptype: &str,
    ) -> Option<Arc<RwLock<dyn RoleManager>>>;
    fn set_named_role_manager(
        &mut self,
        ptype: &str,
        rm: Arc<RwLock<dyn RoleManager>>,
    ) -> Result<()>;
    #[cfg(feature = "logging")]
    fn get_logger(&self) -> &dyn Logger;
    #[cfg(feature = "logging")]
    fn set_logger(&mut self, logger: Box<dyn Logger>);
    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()>
    where
        Self: Sized;
    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()>
    where
        Self: Sized;
    fn set_effector(&mut self, e: Box<dyn Effector>);
    fn enforce<ARGS: EnforceArgs>(&self, rvals: ARGS) -> Result<bool>
    where
        Self: Sized;
    fn enforce_with_context<ARGS: EnforceArgs>(
        &self,
        ctx: EnforceContext,
        rvals: ARGS,
    ) -> Result<bool>
    where
        Self: Sized;
    fn enforce_mut<ARGS: EnforceArgs>(&mut self, rvals: ARGS) -> Result<bool>
    where
        Self: Sized;
    #[cfg(feature = "explain")]
    fn enforce_ex<ARGS: EnforceArgs>(
        &self,
        rvals: ARGS,
    ) -> Result<(bool, Vec<Vec<String>>)>
    where
        Self: Sized;
    fn build_role_links(&mut self) -> Result<()>;
    #[cfg(feature = "incremental")]
    fn build_incremental_role_links(&mut self, d: EventData) -> Result<()>;
    async fn load_policy(&mut self) -> Result<()>;
    async fn load_filtered_policy<'a>(&mut self, f: Filter<'a>) -> Result<()>;
    fn is_filtered(&self) -> bool;
    fn is_enabled(&self) -> bool;
    async fn save_policy(&mut self) -> Result<()>;
    async fn clear_policy(&mut self) -> Result<()>;
    #[cfg(feature = "logging")]
    fn enable_log(&mut self, enabled: bool);
    fn enable_auto_save(&mut self, auto_save: bool);
    fn enable_enforce(&mut self, enabled: bool);
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool);
    #[cfg(feature = "watcher")]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool);
    fn has_auto_save_enabled(&self) -> bool;
    #[cfg(feature = "watcher")]
    fn has_auto_notify_watcher_enabled(&self) -> bool;
    fn has_auto_build_role_links_enabled(&self) -> bool;
}

pub trait IEnforcer: CoreApi + EventEmitter<Event> {}

impl<T> IEnforcer for T where T: CoreApi + EventEmitter<Event> {}
