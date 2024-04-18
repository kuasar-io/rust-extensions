use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::TryFutureExt;
use log::info;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tonic::transport::Server;

pub use cri::api::v1::PodSandboxConfig;

use crate::api::sandbox::v1::controller_server::ControllerServer;
use crate::data::{ContainerData, SandboxData};
use crate::error::Result;
use crate::rpc::SandboxController;
use crate::signal::ExitSignal;

pub mod args;
pub mod config;
pub mod data;
pub mod error;
pub mod rpc;
pub mod signal;
pub mod spec;
pub mod utils;

/// Generated GRPC apis.
pub mod api {
    /// Generated snapshots bindings.
    pub mod sandbox {
        pub mod v1 {
            tonic::include_proto!("containerd.services.sandbox.v1");
        }
    }
}

pub mod cri {
    pub mod api {
        pub mod v1 {
            tonic::include_proto!("runtime.v1");
        }
    }
}

pub mod types {
    tonic::include_proto!("containerd.types");
}

#[derive(Clone, Debug)]
pub struct SandboxOption {
    pub base_dir: String,
    pub sandbox: SandboxData,
}

impl SandboxOption {
    fn new(base_dir: String, sandbox: SandboxData) -> Self {
        Self { base_dir, sandbox }
    }
}

#[derive(Clone, Debug)]
pub struct ContainerOption {
    pub container: ContainerData,
}

impl ContainerOption {
    pub fn new(container: ContainerData) -> Self {
        return Self { container };
    }
}

pub trait Container {
    fn get_data(&self) -> Result<ContainerData>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SandboxStatus {
    Created,
    // the parameter is the pid of the sandbox, if there is one
    Running(u32),
    // first parameter is exit code, second parameter is exit timestamp in nanos
    Stopped(u32, i128),
    Paused,
}

impl ToString for SandboxStatus {
    fn to_string(&self) -> String {
        return match self {
            Self::Created => "created".to_string(),
            Self::Running(_) => "running".to_string(),
            Self::Stopped(_, _) => "stopped".to_string(),
            Self::Paused => "paused".to_string(),
        };
    }
}

#[async_trait]
pub trait Sandboxer {
    type Sandbox: Sandbox + Send + Sync;
    async fn create(&self, id: &str, s: SandboxOption) -> Result<()>;
    async fn start(&self, id: &str) -> Result<()>;
    async fn sandbox(&self, id: &str) -> Result<Arc<Mutex<Self::Sandbox>>>;
    async fn stop(&self, id: &str, force: bool) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}

#[async_trait]
pub trait Sandbox: Sync + Send {
    type Container: Container + Send + Sync;
    fn status(&self) -> Result<SandboxStatus>;
    async fn ping(&self) -> Result<()>;
    async fn container(&self, id: &str) -> Result<&Self::Container>;
    async fn append_container(&mut self, id: &str, option: ContainerOption) -> Result<()>;
    async fn update_container(&mut self, id: &str, option: ContainerOption) -> Result<()>;
    async fn remove_container(&mut self, id: &str) -> Result<()>;
    async fn exit_signal(&self) -> Result<Arc<ExitSignal>>;
    fn get_data(&self) -> Result<SandboxData>;
}

pub async fn run<S>(name: &str, listening_addr: &str, working_dir: &str, sandboxer: S) -> Result<()>
where
    S: Sandboxer + Sync + Send + 'static,
{
    info!("start sandbox plugin: {}", name);
    if Path::new(listening_addr).exists() {
        tokio::fs::remove_file(listening_addr).await?;
    }

    if !Path::new(working_dir).exists() {
        tokio::fs::create_dir_all(working_dir).await?;
    }

    let incoming = {
        let uds = UnixListener::bind(listening_addr)?;
        async_stream::stream! {
            loop {
                let item = uds.accept().map_ok(|(st, _)|unix::UnixStream(st)).await;
                yield item;
            }
        }
    };

    let sandbox_controller = SandboxController::new(working_dir.to_string(), sandboxer);
    let sandbox_server = ControllerServer::new(sandbox_controller);
    Server::builder()
        .add_service(sandbox_server)
        .serve_with_incoming(incoming)
        .await
        .with_context(|| format!("gRPC server"))?;

    Ok(())
}

mod unix {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tonic::transport::server::Connected;

    #[derive(Debug)]
    pub struct UnixStream(pub tokio::net::UnixStream);

    impl Connected for UnixStream {
        type ConnectInfo = UdsConnectInfo;

        fn connect_info(&self) -> Self::ConnectInfo {
            UdsConnectInfo {
                peer_addr: self.0.peer_addr().ok().map(Arc::new),
                peer_cred: self.0.peer_cred().ok(),
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct UdsConnectInfo {
        pub peer_addr: Option<Arc<tokio::net::unix::SocketAddr>>,
        pub peer_cred: Option<tokio::net::unix::UCred>,
    }

    impl AsyncRead for UnixStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for UnixStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}
