use crate::{core_api::IEnforcer, Result};

#[cfg(any(
    feature = "watcher",
    feature = "cached",
    feature = "logging",
    feature = "incremental"
))]
use crate::emitter::EventData;

#[cfg(any(feature = "watcher", feature = "cached", feature = "logging",))]
use crate::emitter::Event;

use async_trait::async_trait;

#[async_trait]
pub trait InternalApi: IEnforcer {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<(bool, Vec<Vec<String>>)>;
}

#[async_trait]
impl<T> InternalApi for T
where
    T: IEnforcer,
{
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .add_policy(sec, ptype, rule.clone())
                .await?
        {
            return Ok(false);
        }

        let rule_added = self.get_mut_model().add_policy(sec, ptype, {
            #[cfg(any(
                feature = "watcher",
                feature = "logging",
                feature = "incremental"
            ))]
            {
                rule.clone()
            }
            #[cfg(all(
                not(feature = "watcher"),
                not(feature = "logging"),
                not(feature = "incremental")
            ))]
            {
                rule
            }
        });
        #[cfg(any(feature = "watcher", feature = "logging"))]
        {
            let event_data =
                EventData::AddPolicy(sec.to_owned(), ptype.to_owned(), {
                    #[cfg(feature = "incremental")]
                    {
                        rule.clone()
                    }
                    #[cfg(not(feature = "incremental"))]
                    {
                        rule
                    }
                });
            #[cfg(feature = "watcher")]
            {
                if rule_added && self.has_auto_notify_watcher_enabled() {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
            #[cfg(not(feature = "watcher"))]
            {
                if rule_added {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
        }
        #[cfg(feature = "cached")]
        {
            if rule_added {
                self.emit(Event::ClearCache, EventData::ClearCache);
            }
        }
        if sec != "g"
            || !rule_added
            || !self.has_auto_build_role_links_enabled()
        {
            return Ok(rule_added);
        }
        #[cfg(not(feature = "incremental"))]
        {
            self.build_role_links()?;
        }
        #[cfg(feature = "incremental")]
        {
            self.build_incremental_role_links(EventData::AddPolicy(
                sec.to_owned(),
                ptype.to_owned(),
                rule,
            ))?;
        }

        Ok(rule_added)
    }

    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .add_policies(sec, ptype, rules.clone())
                .await?
        {
            return Ok(false);
        }

        let rules_added = self.get_mut_model().add_policies(sec, ptype, {
            #[cfg(any(
                feature = "watcher",
                feature = "logging",
                feature = "incremental"
            ))]
            {
                rules.clone()
            }
            #[cfg(all(
                not(feature = "watcher"),
                not(feature = "logging"),
                not(feature = "incremental")
            ))]
            {
                rules
            }
        });
        #[cfg(any(feature = "watcher", feature = "logging"))]
        {
            let event_data =
                EventData::AddPolicies(sec.to_owned(), ptype.to_owned(), {
                    #[cfg(feature = "incremental")]
                    {
                        rules.clone()
                    }
                    #[cfg(not(feature = "incremental"))]
                    {
                        rules
                    }
                });
            #[cfg(feature = "watcher")]
            {
                if rules_added && self.has_auto_notify_watcher_enabled() {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
            #[cfg(not(feature = "watcher"))]
            {
                if rules_added {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
        }
        #[cfg(feature = "cached")]
        {
            if rules_added {
                self.emit(Event::ClearCache, EventData::ClearCache);
            }
        }
        if sec != "g"
            || !rules_added
            || !self.has_auto_build_role_links_enabled()
        {
            return Ok(rules_added);
        }
        #[cfg(not(feature = "incremental"))]
        {
            self.build_role_links()?;
        }
        #[cfg(feature = "incremental")]
        {
            self.build_incremental_role_links(EventData::AddPolicies(
                sec.to_owned(),
                ptype.to_owned(),
                rules,
            ))?;
        }

        Ok(rules_added)
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .remove_policy(sec, ptype, rule.clone())
                .await?
        {
            return Ok(false);
        }

        let rule_removed = self.get_mut_model().remove_policy(sec, ptype, {
            #[cfg(any(
                feature = "watcher",
                feature = "logging",
                feature = "incremental"
            ))]
            {
                rule.clone()
            }
            #[cfg(all(
                not(feature = "watcher"),
                not(feature = "logging"),
                not(feature = "incremental")
            ))]
            {
                rule
            }
        });
        #[cfg(any(feature = "watcher", feature = "logging"))]
        {
            let event_data =
                EventData::RemovePolicy(sec.to_owned(), ptype.to_owned(), {
                    #[cfg(feature = "incremental")]
                    {
                        rule.clone()
                    }
                    #[cfg(not(feature = "incremental"))]
                    {
                        rule
                    }
                });
            #[cfg(feature = "watcher")]
            {
                if rule_removed && self.has_auto_notify_watcher_enabled() {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
            #[cfg(not(feature = "watcher"))]
            {
                if rule_removed {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
        }
        #[cfg(feature = "cached")]
        {
            if rule_removed {
                self.emit(Event::ClearCache, EventData::ClearCache);
            }
        }
        if sec != "g"
            || !rule_removed
            || !self.has_auto_build_role_links_enabled()
        {
            return Ok(rule_removed);
        }
        #[cfg(not(feature = "incremental"))]
        {
            self.build_role_links()?;
        }
        #[cfg(feature = "incremental")]
        {
            self.build_incremental_role_links(EventData::RemovePolicy(
                sec.to_owned(),
                ptype.to_owned(),
                rule,
            ))?;
        }

        Ok(rule_removed)
    }

    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .remove_policies(sec, ptype, rules.clone())
                .await?
        {
            return Ok(false);
        }

        let rules_removed = self.get_mut_model().remove_policies(sec, ptype, {
            #[cfg(any(
                feature = "watcher",
                feature = "logging",
                feature = "incremental"
            ))]
            {
                rules.clone()
            }
            #[cfg(all(
                not(feature = "watcher"),
                not(feature = "logging"),
                not(feature = "incremental")
            ))]
            {
                rules
            }
        });
        #[cfg(any(feature = "watcher", feature = "logging"))]
        {
            let event_data =
                EventData::RemovePolicies(sec.to_owned(), ptype.to_owned(), {
                    #[cfg(feature = "incremental")]
                    {
                        rules.clone()
                    }
                    #[cfg(not(feature = "incremental"))]
                    {
                        rules
                    }
                });
            #[cfg(feature = "watcher")]
            {
                if rules_removed && self.has_auto_notify_watcher_enabled() {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
            #[cfg(not(feature = "watcher"))]
            {
                if rules_removed {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
        }
        #[cfg(feature = "cached")]
        {
            if rules_removed {
                self.emit(Event::ClearCache, EventData::ClearCache);
            }
        }
        if sec != "g"
            || !rules_removed
            || !self.has_auto_build_role_links_enabled()
        {
            return Ok(rules_removed);
        }
        #[cfg(not(feature = "incremental"))]
        {
            self.build_role_links()?;
        }
        #[cfg(feature = "incremental")]
        {
            self.build_incremental_role_links(EventData::RemovePolicies(
                sec.to_owned(),
                ptype.to_owned(),
                rules,
            ))?;
        }

        Ok(rules_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<(bool, Vec<Vec<String>>)> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .remove_filtered_policy(
                    sec,
                    ptype,
                    field_index,
                    field_values.clone(),
                )
                .await?
        {
            return Ok((false, vec![]));
        }

        let (rules_removed, rules) = self
            .get_mut_model()
            .remove_filtered_policy(sec, ptype, field_index, field_values);
        #[cfg(any(feature = "watcher", feature = "logging"))]
        {
            let event_data = EventData::RemoveFilteredPolicy(
                sec.to_owned(),
                ptype.to_owned(),
                rules.clone(),
            );
            #[cfg(feature = "watcher")]
            {
                if rules_removed && self.has_auto_notify_watcher_enabled() {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
            #[cfg(not(feature = "watcher"))]
            {
                if rules_removed {
                    self.emit(Event::PolicyChange, event_data);
                }
            }
        }
        #[cfg(feature = "cached")]
        {
            if rules_removed {
                self.emit(Event::ClearCache, EventData::ClearCache);
            }
        }
        if sec != "g"
            || !rules_removed
            || !self.has_auto_build_role_links_enabled()
        {
            return Ok((rules_removed, rules));
        }
        #[cfg(not(feature = "incremental"))]
        {
            self.build_role_links()?;
        }
        #[cfg(feature = "incremental")]
        {
            self.build_incremental_role_links(
                EventData::RemoveFilteredPolicy(
                    sec.to_owned(),
                    ptype.to_owned(),
                    rules.clone(),
                ),
            )?;
        }

        Ok((rules_removed, rules))
    }
}
