use casbin::prelude::*;

extern crate criterion;

use criterion::{criterion_group, criterion_main, Criterion};

fn await_future<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    #[cfg(feature = "runtime-async-std")]
    {
        async_std::task::block_on(future)
    }

    #[cfg(feature = "runtime-tokio")]
    {
        tokio::runtime::Runtime::new().unwrap().block_on(future)
    }
}

// To save a new baseline to compare against run
// `cargo bench > before`
// on the master branch.
//
// Then install cargo-benchcmp
// `cargo install cargo-benchcmp --force`
//
// Then to compare your changes switch to your branch and run
// `cargo bench > after`
//
// And compare with
// cargo benchcmp before after

fn raw_enforce(r: [&str; 3]) -> bool {
    let policies = [["alice", "data1", "read"], ["bob", "data2", "write"]];
    for policy in &policies {
        if policy == &r {
            return true;
        }
    }
    return false;
}

fn b_benchmark_raw(c: &mut Criterion) {
    c.bench_function("benchmark_raw", |b| {
        b.iter(|| {
            raw_enforce(["alice", "data1", "read"]);
        })
    });
}

fn b_benchmark_basic_model(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/basic_model.conf",
        "examples/basic_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_basic_model", |b| {
        b.iter(|| {
            e.enforce(("alice", "data1", "read")).unwrap();
        })
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_basic_model(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/basic_model.conf",
        "examples/basic_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_basic_model", |b| {
        b.iter(|| {
            e.enforce_mut(("alice", "data1", "read")).unwrap();
        })
    });
}

#[cfg(not(feature = "cached"))]
fn b_benchmark_cached_basic_model(_c: &mut Criterion) {}

fn b_benchmark_rbac_model(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/rbac_model.conf",
        "examples/rbac_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_rbac_model", |b| {
        b.iter(|| {
            e.enforce(("alice", "data2", "read")).unwrap();
        })
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_model(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_model.conf",
        "examples/rbac_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_rbac_model", |b| {
        b.iter(|| {
            e.enforce_mut(("alice", "data2", "read")).unwrap();
        })
    });
}

fn b_benchmark_role_manager_small(c: &mut Criterion) {
    let mut e =
        await_future(Enforcer::new("examples/rbac_model.conf", ())).unwrap();

    e.enable_auto_build_role_links(false);

    // 100 roles, 10 resources.
    await_future(
        e.add_policies(
            (0..100_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 1000 users.
    await_future(
        e.add_grouping_policies(
            (0..1000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    let rm = e.get_role_manager();
    c.bench_function("benchmark_role_manager_small", |b| {
        b.iter(|| {
            (0..100_u64).for_each(|i| {
                rm.write().has_link("user501", &format!("group{}", i), None);
            })
        })
    });
}

fn b_benchmark_rbac_model_small(c: &mut Criterion) {
    let mut e =
        await_future(Enforcer::new("examples/rbac_model.conf", ())).unwrap();

    e.enable_auto_build_role_links(false);

    // 100 roles, 10 resources.
    await_future(
        e.add_policies(
            (0..100_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 1000 users.
    await_future(
        e.add_grouping_policies(
            (0..1000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();
    c.bench_function("benchmark_role_manager_small", |b| {
        b.iter(|| e.enforce(("user501", "data9", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_model_small(c: &mut Criterion) {
    let mut e =
        await_future(CachedEnforcer::new("examples/rbac_model.conf", ()))
            .unwrap();

    e.enable_auto_build_role_links(false);

    // 100 roles, 10 resources.
    await_future(
        e.add_policies(
            (0..100_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 1000 users.
    await_future(
        e.add_grouping_policies(
            (0..1000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();
    c.bench_function("benchmark_cached_rbac_model_small", |b| {
        b.iter(|| e.enforce_mut(("user501", "data9", "read")).unwrap())
    });
}

fn b_benchmark_role_manager_medium(c: &mut Criterion) {
    let mut e =
        await_future(Enforcer::new("examples/rbac_model.conf", ())).unwrap();

    e.enable_auto_build_role_links(false);

    // 1000 roles, 100 resources.
    await_future(
        e.add_policies(
            (0..1000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 10000 users.
    await_future(
        e.add_grouping_policies(
            (0..10000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    let rm = e.get_role_manager();
    c.bench_function("benchmark_role_manager_medium", |b| {
        b.iter(|| {
            (0..1000_u64).for_each(|i| {
                rm.write()
                    .has_link("user5001", &format!("group{}", i), None);
            })
        })
    });
}

fn b_benchmark_rbac_model_medium(c: &mut Criterion) {
    let mut e =
        await_future(Enforcer::new("examples/rbac_model.conf", ())).unwrap();

    e.enable_auto_build_role_links(false);

    // 1000 roles, 100 resources.
    await_future(
        e.add_policies(
            (0..1000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 10000 users.
    await_future(
        e.add_grouping_policies(
            (0..10000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();
    c.bench_function("benchmark_rbac_model_medium", |b| {
        b.iter(|| e.enforce(("user5001", "data15", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_model_medium(c: &mut Criterion) {
    let mut e =
        await_future(CachedEnforcer::new("examples/rbac_model.conf", ()))
            .unwrap();

    e.enable_auto_build_role_links(false);

    // 1000 roles, 100 resources.
    await_future(
        e.add_policies(
            (0..1000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 10000 users.
    await_future(
        e.add_grouping_policies(
            (0..10000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();
    c.bench_function("benchmark_cached_rbac_model_medium", |b| {
        b.iter(|| e.enforce_mut(("user5001", "data15", "read")).unwrap())
    });
}

fn b_benchmark_role_manager_large(c: &mut Criterion) {
    let mut e =
        await_future(Enforcer::new("examples/rbac_model.conf", ())).unwrap();

    e.enable_auto_build_role_links(false);

    // 10000 roles, 1000 resources.
    await_future(
        e.add_policies(
            (0..10000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 100000 users.
    await_future(
        e.add_grouping_policies(
            (0..100000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();

    let rm = e.get_role_manager();
    c.bench_function("benchmark_role_manager_large", |b| {
        b.iter(|| {
            (0..10000_u64).for_each(|i| {
                rm.write()
                    .has_link("user50001", &format!("group{}", i), None);
            })
        })
    });
}

fn b_benchmark_rbac_model_large(c: &mut Criterion) {
    let mut e =
        await_future(Enforcer::new("examples/rbac_model.conf", ())).unwrap();

    e.enable_auto_build_role_links(false);

    // 10000 roles, 1000 resources.
    await_future(
        e.add_policies(
            (0..10000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 100000 users.
    await_future(
        e.add_grouping_policies(
            (0..100000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();
    c.bench_function("b_benchmark_rbac_model_large", |b| {
        b.iter(|| e.enforce(("user50001", "data1500", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_model_large(c: &mut Criterion) {
    let mut e =
        await_future(CachedEnforcer::new("examples/rbac_model.conf", ()))
            .unwrap();

    e.enable_auto_build_role_links(false);

    // 10000 roles, 1000 resources.
    await_future(
        e.add_policies(
            (0..10000_u64)
                .map(|i| {
                    vec![
                        format!("group{}", i),
                        format!("data{}", i / 10),
                        "read".to_owned(),
                    ]
                })
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    // 100000 users.
    await_future(
        e.add_grouping_policies(
            (0..100000)
                .map(|i| vec![format!("user{}", i), format!("group{}", i / 10)])
                .collect::<Vec<Vec<String>>>(),
        ),
    )
    .unwrap();

    e.build_role_links().unwrap();
    c.bench_function("benchmark_cached_rbac_model_large", |b| {
        b.iter(|| e.enforce_mut(("user50001", "data1500", "read")).unwrap())
    });
}

fn b_benchmark_rbac_with_resource_roles(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/rbac_with_resource_roles_model.conf",
        "examples/rbac_with_resource_roles_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_rbac_with_resource_roles", |b| {
        b.iter(|| e.enforce(("alice", "data1", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_with_resource_roles(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_with_resource_roles_model.conf",
        "examples/rbac_with_resource_roles_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_rbac_with_resource_roles", |b| {
        b.iter(|| e.enforce_mut(("alice", "data1", "read")).unwrap());
    });
}

fn b_benchmark_rbac_model_with_domains(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/rbac_with_domains_model.conf",
        "examples/rbac_with_domains_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_rbac_model_with_domains", |b| {
        b.iter(|| e.enforce(("alice", "domain1", "data1", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_model_with_domains(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_with_domains_model.conf",
        "examples/rbac_with_domains_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_rbac_model_with_domains", |b| {
        b.iter(|| {
            e.enforce_mut(("alice", "domain1", "data1", "read"))
                .unwrap()
        })
    });
}

fn b_benchmark_abac_model(c: &mut Criterion) {
    use serde::Serialize;

    let e =
        await_future(Enforcer::new("examples/abac_model.conf", ())).unwrap();

    #[derive(Serialize, Hash)]
    struct Book<'a> {
        owner: &'a str,
    }
    c.bench_function("benchmark_abac_model", |b| {
        b.iter(|| {
            e.enforce(("alice", Book { owner: "alice" }, "read"))
                .unwrap()
        })
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_abac_model(c: &mut Criterion) {
    use serde::Serialize;
    let mut e =
        await_future(CachedEnforcer::new("examples/abac_model.conf", ()))
            .unwrap();

    #[derive(Serialize, Hash)]
    struct Book<'a> {
        owner: &'a str,
    }
    c.bench_function("benchmark_cached_abac_model", |b| {
        b.iter(|| {
            e.enforce_mut(("alice", Book { owner: "alice" }, "read"))
                .unwrap()
        })
    });
}

#[cfg(not(feature = "cached"))]
fn b_benchmark_cached_abac_model(_c: &mut Criterion) {}

fn b_benchmark_key_match(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/keymatch_model.conf",
        "examples/keymatch_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_key_match", |b| {
        b.iter(|| {
            e.enforce(("alice", "/alice_data/resource1", "GET"))
                .unwrap()
        })
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_key_match(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/keymatch_model.conf",
        "examples/keymatch_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_key_match", |b| {
        b.iter(|| {
            e.enforce_mut(("alice", "/alice_data/resource1", "GET"))
                .unwrap()
        })
    });
}

fn b_benchmark_rbac_with_deny(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/rbac_with_deny_model.conf",
        "examples/rbac_with_deny_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_rbac_with_deny", |b| {
        b.iter(|| e.enforce(("alice", "data1", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_rbac_with_deny(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/rbac_with_deny_model.conf",
        "examples/rbac_with_deny_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_rbac_with_deny", |b| {
        b.iter(|| e.enforce_mut(("alice", "data1", "read")).unwrap())
    });
}

fn b_benchmark_priority_model(c: &mut Criterion) {
    let e = await_future(Enforcer::new(
        "examples/priority_model.conf",
        "examples/priority_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark priority model", |b| {
        b.iter(|| e.enforce(("alice", "data1", "read")).unwrap())
    });
}

#[cfg(feature = "cached")]
fn b_benchmark_cached_priority_model(c: &mut Criterion) {
    let mut e = await_future(CachedEnforcer::new(
        "examples/priority_model.conf",
        "examples/priority_policy.csv",
    ))
    .unwrap();
    c.bench_function("benchmark_cached_priority_model", |b| {
        b.iter(|| e.enforce_mut(("alice", "data1", "read")).unwrap())
    });
}

criterion_group!(
    benches,
    b_benchmark_raw,
    b_benchmark_basic_model,
    b_benchmark_cached_basic_model,
    b_benchmark_rbac_model,
    b_benchmark_role_manager_small,
    b_benchmark_rbac_model_small,
    b_benchmark_role_manager_large,
    b_benchmark_role_manager_medium,
    b_benchmark_rbac_model_medium,
    b_benchmark_rbac_model_large,
    b_benchmark_rbac_with_resource_roles,
    b_benchmark_rbac_model_with_domains,
    b_benchmark_abac_model,
    b_benchmark_cached_abac_model,
    b_benchmark_key_match,
    b_benchmark_rbac_with_deny,
    b_benchmark_priority_model,
);
criterion_main!(benches);
