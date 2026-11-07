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

# Custom Functions in Casbin-RS

## Overview

Custom functions in Casbin-RS now support flexible argument types through Rhai's `Dynamic` type. This means you can create custom functions that work with:

- **Strings** (as `ImmutableString`)
- **Integers** (i32 or i64)
- **Booleans**
- **Floats** (f32 or f64)
- **Arrays**
- **Maps**
- And more...

This improvement addresses the limitation where custom functions previously only accepted `ImmutableString` arguments.

## Basic Usage

### Adding a Custom Function

Custom functions are added using the `add_function` method on an `Enforcer` instance:

```rust
use casbin::prelude::*;
use rhai::Dynamic;

// Create your enforcer
let mut e = Enforcer::new("model.conf", "policy.csv").await?;

// Add a custom function
e.add_function(
    "myFunction",
    OperatorFunction::Arg2(|arg1: Dynamic, arg2: Dynamic| {
        // Your custom logic here
        true.into() // Return a Dynamic value
    }),
);
```

## Examples

### 1. String-based Custom Function

For custom functions that work with strings, you can use the helper function `dynamic_to_str`:

```rust
use casbin::model::function_map::dynamic_to_str;

e.add_function(
    "stringContains",
    OperatorFunction::Arg2(|haystack: Dynamic, needle: Dynamic| {
        let haystack_str = dynamic_to_str(&haystack);
        let needle_str = dynamic_to_str(&needle);
        haystack_str.contains(needle_str.as_ref()).into()
    }),
);
```

Or simply convert to String:

```rust
e.add_function(
    "stringMatch",
    OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
        let str1 = s1.to_string();
        let str2 = s2.to_string();
        (str1 == str2).into()
    }),
);
```

### 2. Integer-based Custom Function

```rust
e.add_function(
    "greaterThan",
    OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
        let a_int = a.as_int().unwrap_or(0);
        let b_int = b.as_int().unwrap_or(0);
        (a_int > b_int).into()
    }),
);
```

### 3. Boolean-based Custom Function

```rust
e.add_function(
    "customAnd",
    OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
        let a_bool = a.as_bool().unwrap_or(false);
        let b_bool = b.as_bool().unwrap_or(false);
        (a_bool && b_bool).into()
    }),
);
```

### 4. Multi-argument Custom Function

```rust
e.add_function(
    "between",
    OperatorFunction::Arg3(|val: Dynamic, min: Dynamic, max: Dynamic| {
        let val_int = val.as_int().unwrap_or(0);
        let min_int = min.as_int().unwrap_or(0);
        let max_int = max.as_int().unwrap_or(0);
        (val_int >= min_int && val_int <= max_int).into()
    }),
);
```

### 5. Mixed-type Custom Function

```rust
e.add_function(
    "complexCheck",
    OperatorFunction::Arg3(|name: Dynamic, age: Dynamic, is_admin: Dynamic| {
        let name_str = name.to_string();
        let age_int = age.as_int().unwrap_or(0);
        let admin_bool = is_admin.as_bool().unwrap_or(false);
        
        // Custom logic with different types
        let result = name_str.len() > 3 && age_int >= 18 && admin_bool;
        result.into()
    }),
);
```

## Using Custom Functions in Matchers

Once registered, custom functions can be used in your policy matchers:

```conf
[matchers]
m = greaterThan(r.age, 18) && stringContains(r.path, p.path)
```

## OperatorFunction Variants

The `OperatorFunction` enum supports functions with 0 to 6 arguments:

- `Arg0`: `fn() -> Dynamic`
- `Arg1`: `fn(Dynamic) -> Dynamic`
- `Arg2`: `fn(Dynamic, Dynamic) -> Dynamic`
- `Arg3`: `fn(Dynamic, Dynamic, Dynamic) -> Dynamic`
- `Arg4`: `fn(Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic`
- `Arg5`: `fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic`
- `Arg6`: `fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic`

## Working with Dynamic Types

Rhai's `Dynamic` type provides several methods to extract values:

- `as_int()` - Extract as integer (returns `Result<i64, &str>`)
- `as_bool()` - Extract as boolean (returns `Result<bool, &str>`)
- `as_float()` - Extract as float (returns `Result<f64, &str>`)
- `is_string()` - Check if it's a string
- `into_immutable_string()` - Convert to ImmutableString (consumes the Dynamic)
- `to_string()` - Convert to String (works for any type)

## Backward Compatibility

All existing code continues to work. The change from `ImmutableString` to `Dynamic` is backward compatible because:

1. Strings are automatically converted to `Dynamic` by Rhai
2. The `dynamic_to_str` helper function makes string extraction easy
3. All built-in functions have been updated and tested

## Migration Guide

If you have existing custom functions using `ImmutableString`, update them like this:

**Before:**
```rust
e.add_function(
    "myFunc",
    OperatorFunction::Arg2(
        |s1: ImmutableString, s2: ImmutableString| {
            // logic here
            true.into()
        }
    ),
);
```

**After:**
```rust
e.add_function(
    "myFunc",
    OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
        let str1 = s1.to_string();
        let str2 = s2.to_string();
        // logic here
        true.into()
    }),
);
```

## See Also

- [Casbin Documentation](https://casbin.org/docs/function)
- [Rhai Documentation](https://rhai.rs/book/)
- Test: `test_custom_function_with_dynamic_types` in `src/enforcer.rs`
