use crate::{rbac::RoleManager, Result};

#[cfg(feature = "incremental")]
use crate::emitter::EventData;

use parking_lot::RwLock;

use std::{collections::HashMap, sync::Arc};

mod assertion;
mod default_model;
pub mod function_map;

pub use assertion::{Assertion, AssertionMap};
pub use default_model::DefaultModel;
pub use function_map::*;

pub trait Model: Send + Sync {
    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool;
    fn get_model(&self) -> &HashMap<String, AssertionMap>;
    fn get_mut_model(&mut self) -> &mut HashMap<String, AssertionMap>;
    fn build_role_links(
        &mut self,
        rm_map: &HashMap<String, Arc<RwLock<dyn RoleManager>>>,
    ) -> Result<()>;
    #[cfg(feature = "incremental")]
    fn build_incremental_role_links(
        &mut self,
        rm_map: &HashMap<String, Arc<RwLock<dyn RoleManager>>>,
        d: EventData,
    ) -> Result<()>;
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>)
        -> bool;
    fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> bool;
    fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> bool;
    fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String>;
    fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> bool;
    fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> bool;
    fn clear_policy(&mut self);
    fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> (bool, Vec<Vec<String>>);
    fn to_text(&self) -> String;
    // Downcast support for performance
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}
