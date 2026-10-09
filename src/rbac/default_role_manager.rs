use crate::{
    error::RbacError,
    rbac::{MatchingFn, RoleManager},
    Result,
};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use std::collections::{hash_map::Entry, HashMap, HashSet};

#[cfg(feature = "cached")]
use crate::cache::{Cache, DefaultCache};

#[cfg(feature = "cached")]
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

const DEFAULT_DOMAIN: &str = "DEFAULT";

pub struct DefaultRoleManager {
    all_domains: HashMap<String, StableDiGraph<String, EdgeVariant>>,
    all_domains_indices: HashMap<String, HashMap<String, NodeIndex<u32>>>,
    explicit_links: HashMap<String, HashSet<(String, String)>>,
    #[cfg(feature = "cached")]
    cache: DefaultCache<u64, bool>,
    max_hierarchy_level: usize,
    role_matching_fn: Option<MatchingFn>,
    domain_matching_fn: Option<MatchingFn>,
}

#[derive(Clone, Debug)]
enum EdgeVariant {
    Link,
    Match,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_domains: HashMap::new(),
            all_domains_indices: HashMap::new(),
            explicit_links: HashMap::new(),
            max_hierarchy_level,
            #[cfg(feature = "cached")]
            cache: DefaultCache::new(50),
            role_matching_fn: None,
            domain_matching_fn: None,
        }
    }

    fn get_or_create_role(
        &mut self,
        name: &str,
        domain: Option<&str>,
    ) -> NodeIndex<u32> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        // detect whether this is a new domain creation
        let is_new_domain = !self.all_domains.contains_key(domain);

        let graph = self.all_domains.entry(domain.into()).or_default();

        let role_entry = self
            .all_domains_indices
            .entry(domain.into())
            .or_default()
            .entry(name.into());

        let vacant_entry = match role_entry {
            Entry::Occupied(e) => return *e.get(),
            Entry::Vacant(e) => e,
        };

        let new_role_id = graph.add_node(name.into());
        vacant_entry.insert(new_role_id);

        if let Some(role_matching_fn) = self.role_matching_fn {
            let mut added = false;

            let node_ids: Vec<_> =
                graph.node_indices().filter(|&i| graph[i] != name).collect();

            for existing_role_id in node_ids {
                added |= link_if_matches(
                    graph,
                    role_matching_fn,
                    new_role_id,
                    existing_role_id,
                );

                added |= link_if_matches(
                    graph,
                    role_matching_fn,
                    existing_role_id,
                    new_role_id,
                );
            }

            if added {
                #[cfg(feature = "cached")]
                self.cache.clear();
            }
        }

        // If domain matching function exists and this was a new domain, copy
        // role links from matching domains into the newly created domain so
        // that BFS will see inherited links in this domain's graph.
        if is_new_domain {
            if let Some(domain_matching_fn) = self.domain_matching_fn {
                let keys: Vec<String> =
                    self.all_domains.keys().cloned().collect();
                for d in keys {
                    if d != domain && (domain_matching_fn)(domain, &d) {
                        self.copy_from_domain(&d, domain);
                    }
                }
            }
        }

        new_role_id
    }

    // propagate a Link addition (name1 -> name2) from `domain` into all
    // affected/matching domains. This extracts the inline logic from
    // `add_link` so the code is clearer and avoids nested borrows.
    fn propagate_link_to_affected_domains(
        &mut self,
        name1: &str,
        name2: &str,
        domain: &str,
    ) {
        let name1_owned = name1.to_string();
        let name2_owned = name2.to_string();
        let affected = self.affected_domain_names(domain);
        for d in affected {
            // obtain mutable graph and index map for the affected domain
            let g = self.all_domains.get_mut(&d).unwrap();
            let idx_map =
                self.all_domains_indices.entry(d.clone()).or_default();
            let idx1 = Self::ensure_node_in_graph(g, idx_map, &name1_owned);
            let idx2 = Self::ensure_node_in_graph(g, idx_map, &name2_owned);

            // add Link edge if missing
            let has_link = g
                .edges_connecting(idx1, idx2)
                .any(|e| matches!(*e.weight(), EdgeVariant::Link));
            if !has_link {
                g.add_edge(idx1, idx2, EdgeVariant::Link);
            }
        }

        #[cfg(feature = "cached")]
        self.cache.clear();
    }

    // ensure a node with `name` exists in graph `g` and in the provided
    // `idx_map`. Returns the NodeIndex for the node.
    fn ensure_node_in_graph(
        g: &mut StableDiGraph<String, EdgeVariant>,
        idx_map: &mut HashMap<String, NodeIndex<u32>>,
        name: &str,
    ) -> NodeIndex<u32> {
        if let Some(idx) = idx_map.get(name) {
            *idx
        } else if let Some(idx) = g.node_indices().find(|&i| g[i] == name) {
            idx_map.insert(name.to_string(), idx);
            idx
        } else {
            let ni = g.add_node(name.to_string());
            idx_map.insert(name.to_string(), ni);
            ni
        }
    }

    // return the list of affected domain names (immutable) to avoid nested
    // mutable borrows when performing operations across domains
    fn affected_domain_names(&self, domain: &str) -> Vec<String> {
        if let Some(matcher) = self.domain_matching_fn {
            self.all_domains
                .keys()
                .filter(|d| *d != domain && matcher(d, domain))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    // copy all role links and nodes from `src_domain` graph into `dst_domain` graph
    fn copy_from_domain(&mut self, src_domain: &str, dst_domain: &str) {
        if src_domain == dst_domain {
            return;
        }

        // ensure both graphs exist
        if !self.all_domains.contains_key(src_domain) {
            return;
        }

        let src_graph = match self.all_domains.get(src_domain) {
            Some(g) => g.clone(),
            None => return,
        };

        // ensure dst indices map exists
        let dst_indices = self
            .all_domains_indices
            .entry(dst_domain.into())
            .or_default();

        let dst_graph = self.all_domains.entry(dst_domain.into()).or_default();

        // copy nodes: ensure names exist in dst and capture mapping
        let mut id_map: HashMap<NodeIndex<u32>, NodeIndex<u32>> =
            HashMap::new();
        for src_idx in src_graph.node_indices() {
            let name = &src_graph[src_idx];
            let dst_idx = if let Some(idx) = dst_indices.get(name) {
                *idx
            } else {
                let new_idx = dst_graph.add_node(name.clone());
                dst_indices.insert(name.clone(), new_idx);
                new_idx
            };
            id_map.insert(src_idx, dst_idx);
        }

        // copy edges: for each edge in src_graph, add equivalent edge in dst if missing
        for edge_idx in src_graph.edge_indices() {
            if let Some((src_s, src_t)) = src_graph.edge_endpoints(edge_idx) {
                if let Some(weight) = src_graph.edge_weight(edge_idx) {
                    let dst_s = id_map.get(&src_s).unwrap();
                    let dst_t = id_map.get(&src_t).unwrap();

                    let need_add = match dst_graph.find_edge(*dst_s, *dst_t) {
                        Some(idx) => {
                            // if existing edge is Match but source weight is Link, allow adding Link
                            !matches!(dst_graph[idx], EdgeVariant::Match)
                                || !matches!(weight, &EdgeVariant::Match)
                        }
                        None => true,
                    };

                    if need_add {
                        dst_graph.add_edge(*dst_s, *dst_t, weight.clone());
                    }
                }
            }
        }

        #[cfg(feature = "cached")]
        self.cache.clear();
    }

    // a link in `domain` is still justified if it was added directly to
    // `domain` or to a pattern domain that matches `domain`
    fn link_is_justified(
        &self,
        name1: &str,
        name2: &str,
        domain: &str,
    ) -> bool {
        let key = (name1.to_owned(), name2.to_owned());
        self.explicit_links.iter().any(|(d, links)| {
            links.contains(&key)
                && (d == domain
                    || self.domain_matching_fn.is_some_and(|f| f(domain, d)))
        })
    }

    fn remove_link_edge(
        &mut self,
        name1: &str,
        name2: &str,
        domain: &str,
    ) -> bool {
        use petgraph::visit::EdgeRef;

        let (graph, indices) = match (
            self.all_domains.get_mut(domain),
            self.all_domains_indices.get(domain),
        ) {
            (Some(graph), Some(indices)) => (graph, indices),
            _ => return false,
        };

        let (role1, role2) = match (indices.get(name1), indices.get(name2)) {
            (Some(role1), Some(role2)) => (*role1, *role2),
            _ => return false,
        };

        let edge = graph
            .edges_connecting(role1, role2)
            .find(|e| matches!(*e.weight(), EdgeVariant::Link))
            .map(|e| e.id());

        match edge {
            Some(edge) => {
                graph.remove_edge(edge);
                true
            }
            None => false,
        }
    }

    fn matched_domains(&self, domain: Option<&str>) -> Vec<String> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);
        if let Some(domain_matching_fn) = self.domain_matching_fn {
            self.all_domains
                .keys()
                .filter_map(|key| {
                    if domain_matching_fn(domain, key) {
                        Some(key.to_owned())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
        } else {
            self.all_domains
                .get(domain)
                .map_or(vec![], |_| vec![domain.to_owned()])
        }
    }

    fn domain_has_role(&self, name: &str, domain: Option<&str>) -> bool {
        let matched_domains = self.matched_domains(domain);

        matched_domains.iter().any(|domain| {
            // try to find direct match of role
            if self.all_domains_indices[domain].contains_key(name) {
                true
            } else if let Some(role_matching_fn) = self.role_matching_fn {
                // else if role_matching_fn is set, iterate all graph nodes and try to find matching role
                let graph = &self.all_domains[domain];

                graph
                    .node_weights()
                    .any(|role| role_matching_fn(name, role))
            } else {
                false
            }
        })
    }
}

/// link node of `not_pattern_id` to `maybe_pattern_id` if
/// `not_pattern` matches `maybe_pattern`'s pattern and
/// there doesn't exist a match edge yet
fn link_if_matches(
    graph: &mut StableDiGraph<String, EdgeVariant>,
    role_matching_fn: fn(&str, &str) -> bool,
    not_pattern_id: NodeIndex<u32>,
    maybe_pattern_id: NodeIndex<u32>,
) -> bool {
    let not_pattern = &graph[not_pattern_id];
    let maybe_pattern = &graph[maybe_pattern_id];

    if !role_matching_fn(maybe_pattern, not_pattern) {
        return false;
    }

    let add_edge =
        if let Some(idx) = graph.find_edge(not_pattern_id, maybe_pattern_id) {
            !matches!(graph[idx], EdgeVariant::Match)
        } else {
            true
        };

    if add_edge {
        graph.add_edge(not_pattern_id, maybe_pattern_id, EdgeVariant::Match);

        true
    } else {
        false
    }
}

impl RoleManager for DefaultRoleManager {
    fn clear(&mut self) {
        self.all_domains_indices.clear();
        self.all_domains.clear();
        self.explicit_links.clear();
        #[cfg(feature = "cached")]
        self.cache.clear();
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        if name1 == name2 {
            return;
        }

        self.explicit_links
            .entry(domain.unwrap_or(DEFAULT_DOMAIN).into())
            .or_default()
            .insert((name1.into(), name2.into()));

        let role1 = self.get_or_create_role(name1, domain);
        let role2 = self.get_or_create_role(name2, domain);

        let graph = self
            .all_domains
            .get_mut(domain.unwrap_or(DEFAULT_DOMAIN))
            .unwrap();

        let add_link = if let Some(edge) = graph.find_edge(role1, role2) {
            !matches!(graph[edge], EdgeVariant::Link)
        } else {
            true
        };

        if add_link {
            graph.add_edge(role1, role2, EdgeVariant::Link);

            if let Some(domain_str) = domain {
                self.propagate_link_to_affected_domains(
                    name1, name2, domain_str,
                );
            }

            #[cfg(feature = "cached")]
            self.cache.clear();
        }
    }

    fn matching_fn(
        &mut self,
        role_matching_fn: Option<MatchingFn>,
        domain_matching_fn: Option<MatchingFn>,
    ) {
        self.domain_matching_fn = domain_matching_fn;
        self.role_matching_fn = role_matching_fn;
    }

    fn delete_link(
        &mut self,
        name1: &str,
        name2: &str,
        domain: Option<&str>,
    ) -> Result<()> {
        if name1 == name2 {
            return Ok(());
        }

        if !self.domain_has_role(name1, domain)
            || !self.domain_has_role(name2, domain)
        {
            return Err(
                RbacError::NotFound(format!("{} OR {}", name1, name2)).into()
            );
        }

        let domain_name = domain.unwrap_or(DEFAULT_DOMAIN);

        if let Some(links) = self.explicit_links.get_mut(domain_name) {
            links.remove(&(name1.to_owned(), name2.to_owned()));
        }

        // links added to a pattern domain were copied into every matching
        // domain, so remove those copies too unless something still grants them
        let mut domains = vec![domain_name.to_owned()];
        if domain.is_some() {
            domains.extend(self.affected_domain_names(domain_name));
        }

        let mut removed = false;
        for d in domains {
            if !self.link_is_justified(name1, name2, &d) {
                removed |= self.remove_link_edge(name1, name2, &d);
            }
        }

        if removed {
            #[cfg(feature = "cached")]
            self.cache.clear();
        }

        Ok(())
    }

    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        if name1 == name2 {
            return true;
        }

        #[cfg(feature = "cached")]
        let cache_key = {
            let mut hasher = DefaultHasher::new();
            name1.hash(&mut hasher);
            name2.hash(&mut hasher);
            domain.unwrap_or(DEFAULT_DOMAIN).hash(&mut hasher);
            hasher.finish()
        };

        #[cfg(feature = "cached")]
        if let Some(res) = self.cache.get(&cache_key) {
            return res;
        }

        let matched_domains = self.matched_domains(domain);

        let mut res = false;

        for domain in matched_domains {
            let graph = self.all_domains.get(&domain).unwrap();
            let indices = self.all_domains_indices.get(&domain).unwrap();

            let role1 = if let Some(role1) = indices.get(name1) {
                Some(*role1)
            } else {
                graph.node_indices().find(|&i| {
                    let role_name = &graph[i];

                    role_name == name1
                        || self
                            .role_matching_fn
                            .map(|f| f(name1, role_name))
                            .unwrap_or_default()
                })
            };

            let role1 = if let Some(role1) = role1 {
                role1
            } else {
                continue;
            };

            let mut bfs = matching_bfs::Bfs::new(
                graph,
                role1,
                self.max_hierarchy_level,
                self.role_matching_fn.is_some(),
            );

            while let Some(node) = bfs.next(graph) {
                let role_name = &graph[node];

                if role_name == name2
                    || self
                        .role_matching_fn
                        .map(|f| f(role_name, name2))
                        .unwrap_or_default()
                {
                    res = true;
                    break;
                }
            }
        }

        #[cfg(feature = "cached")]
        self.cache.set(cache_key, res);

        res
    }

    fn get_roles(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let matched_domains = self.matched_domains(domain);

        let res = matched_domains.into_iter().fold(
            HashSet::new(),
            |mut set, domain| {
                let graph = &self.all_domains[&domain];

                if let Some(role_node) = graph.node_indices().find(|&i| {
                    graph[i] == name
                        || self.role_matching_fn.unwrap_or(|_, _| false)(
                            name, &graph[i],
                        )
                }) {
                    let neighbors = matching_bfs::bfs_iterator(
                        graph,
                        role_node,
                        self.role_matching_fn.is_some(),
                    )
                    .map(|i| graph[i].clone());

                    set.extend(neighbors);
                }

                set
            },
        );
        res.into_iter().collect()
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let matched_domains = self.matched_domains(domain);

        let res = matched_domains.into_iter().fold(
            HashSet::new(),
            |mut set, domain| {
                let graph = &self.all_domains[&domain];

                if let Some(role_node) = graph.node_indices().find(|&i| {
                    graph[i] == name
                        || self
                            .role_matching_fn
                            .map(|f| f(name, &graph[i]))
                            .unwrap_or_default()
                }) {
                    let neighbors = graph
                        .neighbors_directed(
                            role_node,
                            petgraph::Direction::Incoming,
                        )
                        .map(|i| graph[i].clone());

                    set.extend(neighbors);
                }

                set
            },
        );

        res.into_iter().collect()
    }
}

mod matching_bfs {
    use super::EdgeVariant;
    use fixedbitset::FixedBitSet;
    use petgraph::graph::NodeIndex;
    use petgraph::stable_graph::StableDiGraph;
    use petgraph::visit::{EdgeRef, VisitMap, Visitable};
    use std::collections::VecDeque;

    #[derive(Clone)]
    pub(super) struct Bfs {
        /// The queue of nodes to visit
        pub queue: VecDeque<NodeIndex<u32>>,
        /// The map of discovered nodes
        pub discovered: FixedBitSet,
        /// Maximum depth
        pub max_depth: usize,
        /// Consider `Match` edges
        pub with_pattern_matching: bool,

        /// Current depth
        depth: usize,
        /// Number of elements until next depth is reached
        depth_elements_remaining: usize,
    }

    impl Bfs {
        /// Create a new **Bfs**, using the graph's visitor map, and put **start**
        /// in the stack of nodes to visit.
        pub fn new(
            graph: &StableDiGraph<String, EdgeVariant>,
            start: NodeIndex<u32>,
            max_depth: usize,
            with_pattern_matching: bool,
        ) -> Self {
            let mut discovered = graph.visit_map();
            discovered.visit(start);

            let mut queue = VecDeque::new();
            queue.push_front(start);

            Bfs {
                queue,
                discovered,
                max_depth,
                with_pattern_matching,
                depth: 0,
                depth_elements_remaining: 1,
            }
        }

        /// Return the next node in the bfs, or **None** if the traversal is done.
        pub fn next(
            &mut self,
            graph: &StableDiGraph<String, EdgeVariant>,
        ) -> Option<NodeIndex<u32>> {
            if self.max_depth <= self.depth {
                return None;
            }

            if let Some(node) = self.queue.pop_front() {
                self.update_depth();

                let mut counter = 0;
                for succ in
                    bfs_iterator(graph, node, self.with_pattern_matching)
                {
                    if self.discovered.visit(succ) {
                        self.queue.push_back(succ);
                        counter += 1;
                    }
                }

                self.depth_elements_remaining += counter;

                Some(node)
            } else {
                None
            }
        }

        fn update_depth(&mut self) {
            self.depth_elements_remaining -= 1;
            if self.depth_elements_remaining == 0 {
                self.depth += 1
            }
        }
    }

    pub(super) fn bfs_iterator(
        graph: &StableDiGraph<String, EdgeVariant>,
        node: NodeIndex<u32>,
        with_matches: bool,
    ) -> Box<dyn Iterator<Item = NodeIndex<u32>> + '_> {
        // outgoing LINK edges of node
        let outgoing_direct_edge = graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .filter_map(|edge| match *edge.weight() {
                EdgeVariant::Link => Some(edge.target()),
                EdgeVariant::Match => None,
            });

        if !with_matches {
            return Box::new(outgoing_direct_edge);
        }

        // x := outgoing LINK edges of node
        // outgoing_match_edge : outgoing MATCH edges of x FOR ALL x
        let outgoing_match_edge = graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .filter(|edge| matches!(*edge.weight(), EdgeVariant::Link))
            .flat_map(move |edge| {
                graph
                    .edges_directed(
                        edge.target(),
                        petgraph::Direction::Outgoing,
                    )
                    .filter_map(|edge| match *edge.weight() {
                        EdgeVariant::Match => Some(edge.target()),
                        EdgeVariant::Link => None,
                    })
            });

        // x := incoming MATCH edges of node
        // sibling_matched_by := outgoing LINK edges of x FOR ALL x
        let sibling_matched_by = graph
            .edges_directed(node, petgraph::Direction::Incoming)
            .filter(|edge| matches!(*edge.weight(), EdgeVariant::Match))
            .flat_map(move |edge| {
                graph
                    .edges_directed(
                        edge.source(),
                        petgraph::Direction::Outgoing,
                    )
                    .filter_map(|edge| match *edge.weight() {
                        EdgeVariant::Link => Some(edge.target()),
                        EdgeVariant::Match => None,
                    })
            });

        Box::new(
            outgoing_direct_edge
                .chain(outgoing_match_edge)
                .chain(sibling_matched_by),
        )
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use petgraph::stable_graph::StableDiGraph;

        #[test]
        fn test_max_depth() {
            let mut deps = StableDiGraph::<String, EdgeVariant>::new();
            let pg = deps.add_node("petgraph".into());
            let fb = deps.add_node("fixedbitset".into());
            let qc = deps.add_node("quickcheck".into());
            let rand = deps.add_node("rand".into());
            let libc = deps.add_node("libc".into());

            deps.extend_with_edges([
                (pg, fb, EdgeVariant::Link),
                (pg, qc, EdgeVariant::Link),
                (qc, rand, EdgeVariant::Link),
                (rand, libc, EdgeVariant::Link),
            ]);

            let mut bfs = Bfs::new(&deps, pg, 2, false);

            let mut nodes = vec![];
            while let Some(x) = bfs.next(&deps) {
                nodes.push(x);
            }

            assert!(nodes.contains(&fb));
            assert!(nodes.contains(&qc));
            assert!(nodes.contains(&rand));
            assert!(!nodes.contains(&libc));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort_unstable();
        v
    }

    #[test]
    fn test_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", None);
        rm.add_link("u2", "g1", None);
        rm.add_link("u3", "g2", None);
        rm.add_link("u4", "g2", None);
        rm.add_link("u4", "g3", None);
        rm.add_link("g1", "g3", None);

        assert_eq!(true, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(true, rm.has_link("u1", "g3", None));
        assert_eq!(true, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(true, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(true, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(true, rm.has_link("u4", "g2", None));
        assert_eq!(true, rm.has_link("u4", "g3", None));

        // test get_roles
        assert_eq!(vec!["g1"], rm.get_roles("u1", None));
        assert_eq!(vec!["g1"], rm.get_roles("u2", None));
        assert_eq!(vec!["g2"], rm.get_roles("u3", None));
        assert_eq!(vec!["g2", "g3"], sort_unstable(rm.get_roles("u4", None)));
        assert_eq!(vec!["g3"], rm.get_roles("g1", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g2", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g3", None));

        // test delete_link
        rm.delete_link("g1", "g3", None).unwrap();
        rm.delete_link("u4", "g2", None).unwrap();
        assert_eq!(true, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(false, rm.has_link("u1", "g3", None));
        assert_eq!(true, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(false, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(true, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(false, rm.has_link("u4", "g2", None));
        assert_eq!(true, rm.has_link("u4", "g3", None));
        assert_eq!(vec!["g1"], rm.get_roles("u1", None));
        assert_eq!(vec!["g1"], rm.get_roles("u2", None));
        assert_eq!(vec!["g2"], rm.get_roles("u3", None));
        assert_eq!(vec!["g3"], rm.get_roles("u4", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g1", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g2", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g3", None));
    }

    #[test]
    fn test_clear() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", None);
        rm.add_link("u2", "g1", None);
        rm.add_link("u3", "g2", None);
        rm.add_link("u4", "g2", None);
        rm.add_link("u4", "g3", None);
        rm.add_link("g1", "g3", None);

        rm.clear();
        assert_eq!(false, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(false, rm.has_link("u1", "g3", None));
        assert_eq!(false, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(false, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(false, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(false, rm.has_link("u4", "g2", None));
        assert_eq!(false, rm.has_link("u4", "g3", None));
    }

    #[test]
    fn test_domain_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));
        rm.add_link("u3", "admin", Some("domain2"));
        rm.add_link("u4", "admin", Some("domain2"));
        rm.add_link("u4", "admin", Some("domain1"));
        rm.add_link("g1", "admin", Some("domain1"));

        assert_eq!(true, rm.has_link("u1", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u1", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain2")));

        assert_eq!(true, rm.has_link("u2", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u2", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u3", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u3", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u3", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u3", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u4", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain2")));

        rm.delete_link("g1", "admin", Some("domain1")).unwrap();

        rm.delete_link("u4", "admin", Some("domain2")).unwrap();

        assert_eq!(true, rm.has_link("u1", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain2")));

        assert_eq!(true, rm.has_link("u2", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u3", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u3", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u3", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u3", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u4", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "admin", Some("domain2")));
    }

    #[test]
    fn test_users() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));

        rm.add_link("u3", "g2", Some("domain2"));
        rm.add_link("u4", "g2", Some("domain2"));

        rm.add_link("u5", "g3", None);

        assert_eq!(
            vec!["u1", "u2"],
            sort_unstable(rm.get_users("g1", Some("domain1")))
        );
        assert_eq!(
            vec!["u3", "u4"],
            sort_unstable(rm.get_users("g2", Some("domain2")))
        );
        assert_eq!(vec!["u5"], rm.get_users("g3", None));
    }

    #[test]
    fn test_pattern_domain() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(3);
        rm.matching_fn(None, Some(key_match));
        rm.add_link("u1", "g1", Some("*"));

        assert!(rm.domain_has_role("u1", Some("domain2")));
    }

    #[test]
    fn test_basic_role_matching() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(Some(key_match), None);
        rm.add_link("bob", "book_group", None);
        rm.add_link("*", "book_group", None);
        rm.add_link("*", "pen_group", None);
        rm.add_link("eve", "pen_group", None);

        assert!(rm.has_link("alice", "book_group", None));
        assert!(rm.has_link("eve", "book_group", None));
        assert!(rm.has_link("bob", "book_group", None));

        assert_eq!(
            vec!["book_group", "pen_group"],
            sort_unstable(rm.get_roles("alice", None))
        );
    }

    #[test]
    fn test_basic_role_matching2() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(Some(key_match), None);
        rm.add_link("alice", "book_group", None);
        rm.add_link("alice", "*", None);
        rm.add_link("bob", "pen_group", None);

        assert!(rm.has_link("alice", "book_group", None));
        assert!(rm.has_link("alice", "pen_group", None));
        assert!(rm.has_link("bob", "pen_group", None));
        assert!(!rm.has_link("bob", "book_group", None));

        assert_eq!(
            vec!["*", "alice", "bob", "book_group", "pen_group"],
            sort_unstable(rm.get_roles("alice", None))
        );

        assert_eq!(vec!["alice"], sort_unstable(rm.get_users("*", None)));
    }

    #[test]
    fn test_cross_domain_role_inheritance_complex() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        rm.add_link("editor", "admin", Some("*"));
        rm.add_link("viewer", "editor", Some("*"));

        rm.add_link("alice", "editor", Some("domain1"));
        rm.add_link("bob", "viewer", Some("domain2"));

        assert!(rm.has_link("alice", "admin", Some("domain1")));
        assert!(rm.has_link("bob", "editor", Some("domain2")));
        assert!(rm.has_link("bob", "admin", Some("domain2")));

        rm.add_link("charlie", "viewer", Some("domain3"));
        assert!(rm.has_link("charlie", "editor", Some("domain3")));
        assert!(rm.has_link("charlie", "admin", Some("domain3")));

        rm.add_link("super_admin", "admin", Some("domain1"));
        assert!(rm.has_link("super_admin", "admin", Some("domain1")));
    }

    #[test]
    fn test_delete_pattern_domain_link() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        rm.add_link("alice", "admin", Some("*"));
        rm.add_link("bob", "admin", Some("domain2"));
        rm.add_link("admin", "super_admin", Some("domain2"));
        assert!(rm.has_link("alice", "admin", Some("domain2")));
        assert!(rm.has_link("alice", "super_admin", Some("domain2")));

        rm.delete_link("alice", "admin", Some("*")).unwrap();
        assert!(!rm.has_link("alice", "admin", Some("*")));
        assert!(!rm.has_link("alice", "admin", Some("domain2")));
        assert!(!rm.has_link("alice", "super_admin", Some("domain2")));
        assert!(rm.has_link("bob", "super_admin", Some("domain2")));

        rm.add_link("carol", "admin", Some("*"));
        rm.add_link("carol", "admin", Some("domain2"));
        rm.delete_link("carol", "admin", Some("*")).unwrap();
        assert!(rm.has_link("carol", "admin", Some("domain2")));
        assert!(!rm.has_link("carol", "admin", Some("domain3")));

        rm.add_link("dave", "admin", Some("*"));
        rm.add_link("dave", "admin", Some("domain2"));
        rm.delete_link("dave", "admin", Some("domain2")).unwrap();
        assert!(rm.has_link("dave", "super_admin", Some("domain2")));
    }
}
