use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
};

use cucumber::World;
use tokio::io;

#[derive(Debug, Default)]
pub struct E2EContext{
    data: HashMap<TypeId, Box<dyn Any>>,
}

impl E2EContext{
    pub fn new() -> Self{
        Default::default()
    }
    pub fn get_driver<T: Any>(&self) -> Option<&T> {
        self.data
            .get(&TypeId::of::<T>())
            .and_then(|x| x.downcast_ref::<T>())
    }

    pub fn insert<T: Any>(&mut self, value: T) {
        self.data.insert(TypeId::of::<T>(), Box::new(value));
    }
}

#[derive(Debug, World, Default)]
pub struct E2EWorld{
    pub context: Arc<E2EContext>,
    pub browser: Option<String>,
    pub application: Option<String>,
    pub user_name: Option<String>,
    pub password: Option<String>,
}

impl E2EWorld {
    async fn new() -> io::Result<Self> {
        Ok(Self {
            context: Default::default(),
            browser: None,
            application: None,
            user_name: None,
            password: None,
        })
    }
}