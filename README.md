<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Apache Casbin (Incubating) Rust Library

Apache Casbin (Incubating) is an effort undergoing incubation at the Apache
Software Foundation (ASF), sponsored by the Apache Incubator PMC.

Incubation is required of all newly accepted projects until a further review
indicates that the infrastructure, communications, and decision making process
have stabilized in a manner consistent with other successful ASF projects.

While incubation status is not necessarily a reflection of the completeness or
stability of the code, it does indicate that the project has yet to be fully
endorsed by the ASF.

Versions published before the Apache migration are historical Casbin community releases. Apache distributions require project and Incubator approval of the source distribution.


[![GitHub Actions](https://github.com/apache/casbin-rs/workflows/CI/badge.svg)](https://github.com/apache/casbin-rs/actions)
[![Codecov](https://codecov.io/gh/apache/casbin-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/apache/casbin-rs)
[![Docs](https://docs.rs/casbin/badge.svg)](https://docs.rs/casbin)
[![Crates.io](https://img.shields.io/crates/v/casbin.svg)](https://crates.io/crates/casbin)
[![crates.io](https://img.shields.io/crates/d/casbin)](https://crates.io/crates/casbin)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

**News**: still worry about how to write the correct Casbin policy? ``Casbin online editor`` is coming to help! Try it at: https://casbin.org/editor/

![casbin Logo](casbin-logo.png)

**Casbin-RS** is a powerful and efficient open-source access control library for Rust projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

| [![golang](https://casbin.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/img/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin) |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| [Casbin](https://github.com/casbin/casbin)                                             | [jCasbin](https://github.com/casbin/jcasbin)                                        | [node-Casbin](https://github.com/casbin/node-casbin)                                        | [PHP-Casbin](https://github.com/php-casbin/php-casbin)                                   |
| production-ready                                                                       | production-ready                                                                    | production-ready                                                                            | production-ready                                                                         |

| [![python](https://casbin.org/img/langs/python.png)](https://github.com/casbin/pycasbin) | [![dotnet](https://casbin.org/img/langs/dotnet.png)](https://github.com/casbin-net/Casbin.NET) | [![c++](https://casbin.org/img/langs/cpp.png)](https://github.com/casbin/casbin-cpp) | [![rust](https://casbin.org/img/langs/rust.png)](https://github.com/apache/casbin-rs) |
|------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| [PyCasbin](https://github.com/casbin/pycasbin)                                           | [Casbin.NET](https://github.com/casbin-net/Casbin.NET)                                         | [Casbin-CPP](https://github.com/casbin/casbin-cpp)                                   | [Casbin-RS](https://github.com/apache/casbin-rs)                                      |
| production-ready                                                                         | production-ready                                                                               | production-ready                                                                     | production-ready                                                                      |

## Installation

Add this package to `Cargo.toml` of your project. (Check https://crates.io/crates/casbin for right version)

```toml
[dependencies]
casbin = { version = "2.8.0", default-features = false, features = ["runtime-async-std", "logging", "incremental"] }
tokio = { version = "1.10.0", features = ["fs", "io-util"] }
```

**Warning**: `tokio v1.0` or later is supported from `casbin v2.0.6`, we recommend that you upgrade the relevant components to ensure that they work properly. The last version that supports `tokio v0.2` is `casbin v2.0.5` , you can choose according to your needs.

## Get started

1. New a Casbin enforcer with a model file and a policy file:

```rust

use casbin::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let mut e = Enforcer::new("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv").await?;
    e.enable_log(true);

    e.enforce(("alice", "domain1", "data1", "read"))?;
    Ok(())
}
```

2. Add an enforcement hook into your code right before the access happens:

    ```rust
    let sub = "alice"; // the user that wants to access a resource.
    let obj = "data1"; // the resource that is going to be accessed.
    let act = "read"; // the operation that the user performs on the resource.

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            // permit alice to read data1
        } else {
            // deny the request
        }
    } else {
        // error occurs
    }
    ```
💡 Please note that the Enforcer instance is not thread-safe, so in order to use it
in a environment where multiple threads might access it, you have to protect it
using an RwLock like so: `let e = Arc::new(RwLock::new(e));`.

## Table of contents

- [Supported models](#supported-models)
- [How it works?](#how-it-works)
- [Features](#features)
- [Documentation](#documentation)
- [Online editor](#online-editor)
- [Tutorials](#tutorials)
- [Policy management](#policy-management)
- [Policy persistence](#policy-persistence)
- [Role manager](#role-manager)
- [Examples](#examples)
- [Middlewares](#middlewares)
- [Our adopters](#our-adopters)

## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
4. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like ``write-article``, ``read-log``. It doesn't control the access to a specific article or log.
5. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
6. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
7. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
8. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like ``resource.Owner`` can be used to get the attribute for a resource.
9. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like ``/res/*``, ``/res/:id`` and HTTP methods like ``GET``, ``POST``, ``PUT``, ``DELETE``.
10. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
11. **Priority**: the policy rules can be prioritized like firewall rules.

## How it works?

In casbin-rs, an access control model is abstracted into a CONF file based on the **PERM metamodel (Policy, Effect, Request, Matchers)**. So switching or upgrading the authorization mechanism for a project is just as simple as modifying a configuration. You can customize your own access control model by combining the available models. For example, you can get RBAC roles and ABAC attributes together inside one model and share one set of policy rules.

The most basic and simplest model in casbin-rs is ACL. ACL's model CONF is:

```ini
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

An example policy for ACL model is like:

```
p, alice, data1, read
p, bob, data2, write
```

It means:

- alice can read data1
- bob can write data2

## Features

What casbin-rs does:

1. enforce the policy in the classic ``{subject, object, action}`` form or a customized form as you defined, both allow and deny authorizations are supported.
2. handle the storage of the access control model and its policy.
3. manage the role-user mappings and role-role mappings (aka role hierarchy in RBAC).
4. support built-in superuser like ``root`` or ``administrator``. A superuser can do anything without explict permissions.
5. multiple built-in operators to support the rule matching. For example, ``keyMatch`` can map a resource key ``/foo/bar`` to the pattern ``/foo*``.

What casbin-rs does NOT do:

1. authentication (aka verify ``username`` and ``password`` when a user logs in)
2. manage the list of users or roles. I believe it's more convenient for the project itself to manage these entities. Users usually have their passwords, and casbin-rs is not designed as a password container. However, casbin-rs stores the user-role mapping for the RBAC scenario. 

## Documentation

https://casbin.org/docs/overview

## Online editor

You can also use the online editor (http://casbin.org/editor/) to write your casbin-rs model and policy in your web browser. It provides functionality such as ``syntax highlighting`` and ``code completion``, just like an IDE for a programming language.

## Tutorials

https://casbin.org/docs/tutorials

## Policy management

casbin-rs provides two sets of APIs to manage permissions:

- [Management API](https://github.com/apache/casbin-rs/blob/master/src/management_api.rs): the primitive API that provides full support for casbin-rs policy management. See [here](https://github.com/apache/casbin-rs/blob/master/src/management_api.rs) for examples.
- [RBAC API](https://github.com/apache/casbin-rs/blob/master/src/rbac_api.rs): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code. See [here](https://github.com/apache/casbin-rs/blob/master/src/rbac_api.rs) for examples.

We also provide a web-based UI for model management and policy management:

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy persistence

* https://casbin.org/docs/adapters
* There also is [example code on how to preload an existing policy into an adapter](https://github.com/casbin-rs/examples/blob/master/actix-middleware-example/src/main.rs#L73). 

## Role manager

https://casbin.org/docs/role-managers

## Examples

Model | Model file | Policy file
----|------|----
ACL | [basic_model.conf](https://github.com/apache/casbin-rs/blob/master/examples/basic_model.conf) | [basic_policy.csv](https://github.com/apache/casbin-rs/blob/master/examples/basic_policy.csv)
ACL with superuser | [basic_model_with_root.conf](https://github.com/apache/casbin-rs/blob/master/examples/basic_with_root_model.conf) | [basic_policy.csv](https://github.com/apache/casbin-rs/blob/master/examples/basic_policy.csv)
ACL without users | [basic_model_without_users.conf](https://github.com/apache/casbin-rs/blob/master/examples/basic_without_users_model.conf) | [basic_policy_without_users.csv](https://github.com/apache/casbin-rs/blob/master/examples/basic_without_users_policy.csv)
ACL without resources | [basic_model_without_resources.conf](https://github.com/apache/casbin-rs/blob/master/examples/basic_without_resources_model.conf) | [basic_policy_without_resources.csv](https://github.com/apache/casbin-rs/blob/master/examples/basic_without_resources_policy.csv)
RBAC | [rbac_model.conf](https://github.com/apache/casbin-rs/blob/master/examples/rbac_model.conf)  | [rbac_policy.csv](https://github.com/apache/casbin-rs/blob/master/examples/rbac_policy.csv)
RBAC with resource roles | [rbac_model_with_resource_roles.conf](https://github.com/apache/casbin-rs/blob/master/examples/rbac_with_resource_roles_model.conf)  | [rbac_policy_with_resource_roles.csv](https://github.com/apache/casbin-rs/blob/master/examples/rbac_with_resource_roles_policy.csv)
RBAC with domains/tenants | [rbac_model_with_domains.conf](https://github.com/apache/casbin-rs/blob/master/examples/rbac_with_domains_model.conf)  | [rbac_policy_with_domains.csv](https://github.com/apache/casbin-rs/blob/master/examples/rbac_with_domains_policy.csv)
ABAC | [abac_model.conf](https://github.com/apache/casbin-rs/blob/master/examples/abac_model.conf)  | N/A
RESTful | [keymatch_model.conf](https://github.com/apache/casbin-rs/blob/master/examples/keymatch_model.conf)  | [keymatch_policy.csv](https://github.com/apache/casbin-rs/blob/master/examples/keymatch_policy.csv)
Deny-override | [rbac_model_with_deny.conf](https://github.com/apache/casbin-rs/blob/master/examples/rbac_with_deny_model.conf)  | [rbac_policy_with_deny.csv](https://github.com/apache/casbin-rs/blob/master/examples/rbac_with_deny_policy.csv)
Priority | [priority_model.conf](https://github.com/apache/casbin-rs/blob/master/examples/priority_model.conf)  | [priority_policy.csv](https://github.com/apache/casbin-rs/blob/master/examples/priority_policy.csv)

## Middlewares

Authz middlewares for web frameworks: https://casbin.org/docs/middlewares

## Our adopters

https://casbin.org/docs/adopters

## Contributors

This project exists thanks to all the people who contribute. 
<a href="https://github.com/apache/casbin-rs/graphs/contributors"><img src="https://opencollective.com/casbin-rs/contributors.svg?width=890&button=false" /></a>

## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=apache/casbin-rs&type=Date)](https://star-history.dera.page/#apache/casbin-rs&Date)

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.
- https://github.com/apache/casbin-rs/issues
- https://discord.gg/S5UjpzGZjN
