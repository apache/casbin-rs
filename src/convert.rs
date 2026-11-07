#![allow(non_snake_case)]

use crate::{Adapter, DefaultModel, Model, NullAdapter, Result};

#[cfg(not(target_arch = "wasm32"))]
use crate::FileAdapter;

use async_trait::async_trait;
use rhai::{serde::to_dynamic, Dynamic};
use serde::Serialize;

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

#[async_trait]
pub trait TryIntoModel: Send + Sync {
    async fn try_into_model(self) -> Result<Box<dyn Model>>;
}

#[async_trait]
pub trait TryIntoAdapter: Send + Sync {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>>;
}

#[async_trait]
impl TryIntoModel for &'static str {
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(Box::new(DefaultModel::from_file(self).await?))
        }
        #[cfg(target_arch = "wasm32")]
        {
            Ok(Box::new(DefaultModel::from_str(self).await?))
        }
    }
}

#[async_trait]
impl<T> TryIntoModel for Option<T>
where
    T: TryIntoModel,
{
    #[allow(clippy::box_default)]
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        if let Some(m) = self {
            m.try_into_model().await
        } else {
            Ok(Box::new(DefaultModel::default()))
        }
    }
}

#[async_trait]
impl TryIntoAdapter for &'static str {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(Box::new(FileAdapter::new(self)))
        }

        #[cfg(target_arch = "wasm32")]
        {
            Ok(Box::new(NullAdapter))
        }
    }
}

#[async_trait]
impl<T> TryIntoAdapter for Option<T>
where
    T: TryIntoAdapter,
{
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        if let Some(a) = self {
            a.try_into_adapter().await
        } else {
            Ok(Box::new(NullAdapter))
        }
    }
}

#[allow(clippy::unit_arg)]
#[async_trait]
impl TryIntoAdapter for () {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        Ok(Box::new(NullAdapter))
    }
}

#[async_trait]
impl<T> TryIntoModel for T
where
    T: Model + 'static,
{
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        Ok(Box::new(self))
    }
}

#[async_trait]
impl<T> TryIntoAdapter for T
where
    T: Adapter + 'static,
{
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        Ok(Box::new(self))
    }
}

pub trait EnforceArgs {
    fn try_into_vec(self) -> Result<Vec<Dynamic>>;
    fn cache_key(&self) -> u64;
}

impl<T> EnforceArgs for Vec<T>
where
    T: Into<Dynamic> + Hash + Clone,
{
    fn try_into_vec(self) -> Result<Vec<Dynamic>> {
        Ok(self.into_iter().map(|x| x.into()).collect())
    }

    fn cache_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

macro_rules! impl_args {
    ($($p:ident),*) => {
        impl<$($p: Serialize + Hash),*> EnforceArgs for ($($p,)*)
        {
            fn try_into_vec(self) -> Result<Vec<Dynamic>> {
                let ($($p,)*) = self;
                let _v = vec![$(to_dynamic($p)?,)*];

                Ok(_v)
            }

            fn cache_key(&self) -> u64 {
                let ($($p,)*) = self;
                let mut _hasher = DefaultHasher::new();

                $($p.hash(&mut _hasher);)*

                _hasher.finish()
            }
        }

        impl_args!(@pop $($p),*);
    };
    (@pop) => {
    };
    (@pop $head:ident) => {
        impl_args!();
    };
    (@pop $head:ident $(, $tail:ident)+) => {
        impl_args!($($tail),*);
    };
}

impl_args!(A, B, C, D, E, F, G, H, J, K, L, M, N, P, Q, R, S, T, U, V);
