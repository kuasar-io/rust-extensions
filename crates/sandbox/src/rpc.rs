use log::{debug, info};
use prost_types::Timestamp;
use time::OffsetDateTime;
use tokio::fs::{create_dir_all, remove_dir_all};
use tonic::{Request, Response, Status};

use crate::api::sandbox::v1::controller_server::Controller;
use crate::api::sandbox::v1::*;
use crate::data::{ContainerData, ProcessData, SandboxData};
use crate::{Container, ContainerOption, Sandbox, SandboxOption, SandboxStatus, Sandboxer};

use crate::utils::cleanup_mounts;

const SANDBOX_STATUS_READY: &str = "SANDBOX_READY";
const SANDBOX_STATUS_NOTREADY: &str = "SANDBOX_NOTREADY";

macro_rules! ignore_not_found {
    ($res: expr) => {{
        match $res {
            Ok(x) => Ok(x),
            Err(e) => match e {
                crate::error::Error::NotFound(_) => Ok(Default::default()),
                _ => Err(e),
            },
        }
    }};
}

pub struct SandboxController<S> {
    dir: String,
    sandboxer: S,
}

impl<S> SandboxController<S> {
    pub fn new(dir: String, sandboxer: S) -> Self {
        Self { dir, sandboxer }
    }
}

#[tonic::async_trait]
impl<S> Controller for SandboxController<S>
where
    S: Sandboxer + Send + Sync + 'static,
{
    async fn create(
        &self,
        request: Request<ControllerCreateRequest>,
    ) -> Result<Response<ControllerCreateResponse>, Status> {
        let req = request.get_ref();
        let sandbox_data: SandboxData = SandboxData::new(req);
        info!("create a new sandbox {:?}", sandbox_data);
        if sandbox_data.id.is_empty() {
            return Err(tonic::Status::invalid_argument("sandbox id is empty"));
        }
        let base_dir = format!("{}/{}", self.dir, sandbox_data.id);
        create_dir_all(&*base_dir).await?;
        let opt = SandboxOption::new(base_dir, sandbox_data);
        self.sandboxer.create(&*req.sandbox_id, opt).await?;
        let resp = ControllerCreateResponse {
            sandbox_id: req.sandbox_id.to_string(),
        };
        Ok(Response::new(resp))
    }

    async fn start(
        &self,
        request: tonic::Request<ControllerStartRequest>,
    ) -> Result<tonic::Response<ControllerStartResponse>, tonic::Status> {
        let req = request.get_ref();
        info!("start sandbox {}", req.sandbox_id);
        self.sandboxer.start(&req.sandbox_id).await?;

        let sandbox_mutex = self.sandboxer.sandbox(&req.sandbox_id).await?;
        let sandbox = sandbox_mutex.lock().await;
        let res = match sandbox.get_data() {
            Ok(s) => s,
            Err(e) => {
                self.sandboxer
                    .stop(&req.sandbox_id, true)
                    .await
                    .unwrap_or_default();
                return Err(e.into());
            }
        };
        let pid = match sandbox.status() {
            Ok(SandboxStatus::Running(pid)) => pid,
            Err(e) => {
                self.sandboxer
                    .stop(&req.sandbox_id, true)
                    .await
                    .unwrap_or_default();
                return Err(e.into());
            }
            Ok(status) => {
                self.sandboxer
                    .stop(&req.sandbox_id, true)
                    .await
                    .unwrap_or_default();
                return Err(tonic::Status::new(
                    tonic::Code::Internal,
                    format!("sandbox status is {}", status.to_string()),
                ));
            }
        };

        let resp = ControllerStartResponse {
            sandbox_id: req.sandbox_id.to_string(),
            pid,
            created_at: res.created_at.map(|x| x.into()),
            labels: Default::default(),
            task_address: res.task_address.clone(),
        };
        info!("start sandbox {:?} returns successfully", resp);
        Ok(Response::new(resp))
    }

    async fn platform(
        &self,
        _request: Request<ControllerPlatformRequest>,
    ) -> Result<Response<ControllerPlatformResponse>, Status> {
        // TODO add more os and arch support,
        // maybe we has to add a new function to our Sandboxer trait
        let platform = crate::types::Platform {
            os: "linux".to_string(),
            architecture: "x86".to_string(),
            variant: "".to_string(),
        };
        let resp = ControllerPlatformResponse {
            platform: Some(platform),
        };
        Ok(Response::new(resp))
    }

    async fn prepare(
        &self,
        request: Request<PrepareRequest>,
    ) -> Result<Response<PrepareResponse>, Status> {
        let req = request.get_ref();
        let sandbox_mutex = self.sandboxer.sandbox(&*req.sandbox_id).await?;
        let mut sandbox = sandbox_mutex.lock().await;
        return if req.exec_id.is_empty() {
            let container_data = ContainerData::new(req);
            info!(
                "append a container {:?} to sandbox {}",
                container_data, req.sandbox_id
            );
            let opt = ContainerOption::new(container_data);
            sandbox.append_container(&*req.container_id, opt).await?;
            let container = sandbox.container(&*req.container_id).await?;
            let data = container.get_data()?;
            let resp = PrepareResponse {
                bundle: data.bundle.to_string(),
            };
            Ok(Response::new(resp))
        } else {
            let process_date = ProcessData::new(req);
            info!(
                "append a process {:?} to container {} of sandbox {}",
                process_date, req.container_id, req.sandbox_id
            );
            let container = sandbox.container(&*req.container_id).await?;
            let mut data = container.get_data()?;
            data.processes.push(process_date);
            let opt = ContainerOption::new(data);
            sandbox.update_container(&*req.container_id, opt).await?;
            Ok(Response::new(PrepareResponse {
                bundle: "".to_string(),
            }))
        };
    }

    async fn purge(
        &self,
        request: Request<PurgeRequest>,
    ) -> Result<Response<PurgeResponse>, Status> {
        let req = request.get_ref();
        let sandbox_mutex = self.sandboxer.sandbox(&*req.sandbox_id).await?;
        let mut sandbox = sandbox_mutex.lock().await;
        return if req.exec_id.is_empty() {
            info!(
                "remove container {} from sandbox {}",
                req.container_id, req.sandbox_id
            );
            sandbox.remove_container(&*req.container_id).await?;
            Ok(Response::new(PurgeResponse {}))
        } else {
            info!(
                "remove process {} from container {} of sandbox {}",
                req.exec_id, req.container_id, req.sandbox_id
            );
            let container = sandbox.container(&*req.container_id).await?;
            let mut data = container.get_data()?;
            data.processes.retain(|x| x.id != req.exec_id);
            let opt = ContainerOption::new(data);
            sandbox.update_container(&*req.container_id, opt).await?;
            Ok(Response::new(PurgeResponse {}))
        };
    }

    async fn update_resources(
        &self,
        _request: Request<UpdateResourcesRequest>,
    ) -> Result<Response<UpdateResourcesResponse>, Status> {
        // TODO support update resource
        return Ok(Response::new(UpdateResourcesResponse {}));
    }

    async fn stop(
        &self,
        request: Request<ControllerStopRequest>,
    ) -> Result<Response<ControllerStopResponse>, Status> {
        let req = request.get_ref();
        info!("stop sandbox {}", req.sandbox_id);
        ignore_not_found!(self.sandboxer.stop(&*req.sandbox_id, true).await)?;
        info!("stop sandbox {} returns successfully", req.sandbox_id);
        Ok(Response::new(ControllerStopResponse {}))
    }

    async fn wait(
        &self,
        request: tonic::Request<ControllerWaitRequest>,
    ) -> Result<tonic::Response<ControllerWaitResponse>, tonic::Status> {
        let req = request.get_ref();
        let exit_signal = {
            let sandbox_mutex = self.sandboxer.sandbox(&*req.sandbox_id).await?;
            let sandbox = sandbox_mutex.lock().await;
            sandbox.exit_signal().await?
        };

        exit_signal.wait().await;
        let sandbox_mutex = self.sandboxer.sandbox(&*req.sandbox_id).await?;
        let sandbox = sandbox_mutex.lock().await;
        let mut wait_resp = ControllerWaitResponse {
            exit_status: 0,
            exited_at: None,
        };
        if let SandboxStatus::Stopped(code, timestamp) = sandbox.status()? {
            let offset_ts = OffsetDateTime::from_unix_timestamp_nanos(timestamp)
                .map_err(|_e| tonic::Status::internal("failed to parse the timestamp"))?;
            let ts = Timestamp {
                seconds: offset_ts.unix_timestamp(),
                nanos: offset_ts.nanosecond() as i32,
            };
            wait_resp.exit_status = code;
            wait_resp.exited_at = Some(ts);
        }
        info!("wait sandbox {} returns {:?}", req.sandbox_id, wait_resp);
        Ok(Response::new(wait_resp))
    }

    async fn status(
        &self,
        request: tonic::Request<ControllerStatusRequest>,
    ) -> Result<tonic::Response<ControllerStatusResponse>, tonic::Status> {
        let req = request.get_ref();
        let sandbox_mutex = self.sandboxer.sandbox(&*req.sandbox_id).await?;
        let sandbox = sandbox_mutex.lock().await;
        // TODO the state should match the definition in containerd
        let (state, pid) = match sandbox.status()? {
            SandboxStatus::Created => (SANDBOX_STATUS_NOTREADY.to_string(), 0),
            SandboxStatus::Running(pid) => (SANDBOX_STATUS_READY.to_string(), pid),
            SandboxStatus::Stopped(_, _) => (SANDBOX_STATUS_NOTREADY.to_string(), 0),
            SandboxStatus::Paused => (SANDBOX_STATUS_NOTREADY.to_string(), 0),
        };
        let (task_address, created_at, exited_at) = {
            let data = sandbox.get_data()?;
            (
                data.task_address,
                data.created_at.map(|x| x.into()),
                data.exited_at.map(|x| x.into()),
            )
        };
        debug!("status sandbox {} returns {:?}", req.sandbox_id, state);
        // TODO add verbose support
        return Ok(Response::new(ControllerStatusResponse {
            sandbox_id: req.sandbox_id.to_string(),
            pid,
            state,
            task_address,
            info: Default::default(),
            created_at,
            exited_at,
            extra: None,
        }));
    }

    async fn shutdown(
        &self,
        request: tonic::Request<ControllerShutdownRequest>,
    ) -> Result<tonic::Response<ControllerShutdownResponse>, tonic::Status> {
        let req = request.get_ref();
        info!("shutdown sandbox {}", req.sandbox_id);
        ignore_not_found!(self.sandboxer.delete(&*req.sandbox_id).await)?;
        let base_dir = format!("{}/{}", self.dir, req.sandbox_id);
        // Ignore clean up error
        cleanup_mounts(&base_dir).await.unwrap_or_default();
        remove_dir_all(&*base_dir).await.unwrap_or_default();
        return Ok(Response::new(ControllerShutdownResponse {}));
    }
}
