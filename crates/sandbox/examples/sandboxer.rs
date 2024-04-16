use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

use containerd_sandbox::data::{ContainerData, SandboxData};
use containerd_sandbox::error::Result;
use containerd_sandbox::signal::ExitSignal;
use containerd_sandbox::{
    run, Container, ContainerOption, Sandbox, SandboxOption, SandboxStatus, Sandboxer,
};

pub struct ExampleSandboxer {
    sandboxes: Arc<RwLock<HashMap<String, Arc<Mutex<ExampleSandbox>>>>>,
}

#[derive(Debug)]
pub struct ExampleSandbox {
    status: SandboxStatus,
    data: SandboxData,
    containers: HashMap<String, ExampleContainer>,
}

#[derive(Clone, Debug)]
pub struct ExampleContainer {
    data: ContainerData,
}

#[async_trait]
impl Sandboxer for ExampleSandboxer {
    type Sandbox = ExampleSandbox;

    async fn create(&self, id: &str, s: SandboxOption) -> Result<()> {
        let sandbox = ExampleSandbox {
            status: SandboxStatus::Created,
            data: s.sandbox,
            containers: Default::default(),
        };
        self.sandboxes
            .write()
            .await
            .insert(id.to_string(), Arc::new(Mutex::new(sandbox)));
        Ok(())
    }

    async fn start(&self, id: &str) -> Result<()> {
        let sandbox_mutex = self
            .sandboxes
            .read()
            .await
            .get(id)
            .ok_or(anyhow!("Not found: {}", id))?
            .clone();
        let mut sandbox = sandbox_mutex.lock().await;
        sandbox.status = SandboxStatus::Running(7000000);
        Ok(())
    }

    async fn sandbox(&self, id: &str) -> Result<Arc<Mutex<Self::Sandbox>>> {
        let sandbox = self
            .sandboxes
            .read()
            .await
            .get(id)
            .ok_or(anyhow!("Not found: {}", id))?
            .clone();
        return Ok(sandbox);
    }

    async fn stop(&self, id: &str, _force: bool) -> Result<()> {
        let sandbox_mutex = self
            .sandboxes
            .read()
            .await
            .get(id)
            .ok_or(anyhow!("Not found: {}", id))?
            .clone();
        let mut sandbox = sandbox_mutex.lock().await;
        sandbox.status = SandboxStatus::Stopped(0, 0);
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.sandboxes.write().await.remove(id);
        Ok(())
    }
}

#[async_trait]
impl Sandbox for ExampleSandbox {
    type Container = ExampleContainer;

    fn status(&self) -> Result<SandboxStatus> {
        Ok(self.status.clone())
    }

    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn container(&self, id: &str) -> Result<&Self::Container> {
        let container = self
            .containers
            .get(id)
            .ok_or(anyhow!("Not found: {}", id))?;
        Ok(container)
    }

    async fn append_container(&mut self, id: &str, option: ContainerOption) -> Result<()> {
        let container = ExampleContainer {
            data: option.container,
        };
        self.containers.insert(id.to_string(), container);
        Ok(())
    }

    async fn update_container(&mut self, id: &str, option: ContainerOption) -> Result<()> {
        let container = self
            .containers
            .get_mut(id)
            .ok_or(anyhow!("Not found: {}", id))?;
        *container = ExampleContainer {
            data: option.container,
        };
        Ok(())
    }

    async fn remove_container(&mut self, id: &str) -> Result<()> {
        self.containers.remove(id);
        Ok(())
    }

    async fn exit_signal(&self) -> Result<Arc<ExitSignal>> {
        let exit = Arc::new(ExitSignal::default());
        Ok(exit)
    }

    fn get_data(&self) -> Result<SandboxData> {
        Ok(self.data.clone())
    }
}

impl Container for ExampleContainer {
    fn get_data(&self) -> Result<ContainerData> {
        Ok(self.data.clone())
    }
}

#[tokio::main]
async fn main() {
    let sandboxer = ExampleSandboxer {
        sandboxes: Default::default(),
    };
    run("io.containerd.sandboxer.example.v1", "", "", sandboxer)
        .await
        .unwrap();
}
