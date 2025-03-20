use std::ops::DerefMut;

use log::{debug, info, warn};
use prost_types::Timestamp;
use time::OffsetDateTime;
use tokio::fs::{create_dir_all, remove_dir_all};
use tonic::{Request, Response, Status};

use crate::api::sandbox::v1::controller_server::Controller;
use crate::api::sandbox::v1::*;
use crate::data::{ContainerData, ProcessData, ProcessResource, SandboxData, TaskResources};
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
        let opt = SandboxOption::new(base_dir.clone(), sandbox_data);
        if let Err(e) = self.sandboxer.create(&*req.sandbox_id, opt).await {
            if let Err(re) = remove_dir_all(base_dir).await {
                warn!("roll back in sandbox create rmdir: {}", re);
            }
            return Err(e.into());
        }
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
            address: res.task_address.clone(),
            version: 2,
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

    async fn update(
        &self,
        request: Request<ControllerUpdateRequest>,
    ) -> Result<Response<ControllerUpdateResponse>, Status> {
        let req = request.get_ref();
        info!("update resource of sandbox {}", req.sandbox_id);
        // only handle extensions.tasks update
        if !req.fields.iter().any(|x| x == "extensions.tasks") {
            warn!("only support updating extensions.tasks");
            return Ok(Response::new(ControllerUpdateResponse {}));
        }
        let (tasks_any, tasks) = if let Some(sb) = &req.sandbox {
            if let Some(a) = sb.extensions.get("tasks") {
                let tasks = serde_json::from_slice(a.value.as_slice()).map_err(|e| {
                    Status::invalid_argument(format!("failed to unmarshal tasks: {}", e))
                })?;
                let ta = crate::data::Any {
                    type_url: a.type_url.clone(),
                    value: a.value.clone(),
                };
                (ta, tasks)
            } else {
                return Err(Status::invalid_argument(
                    "no tasks key in sandbox extensions when update",
                ))?;
            }
        } else {
            return Err(Status::invalid_argument("sandbox is none when update"))?;
        };

        let mut data = {
            let sandbox_mutex = self.sandboxer.sandbox(&*req.sandbox_id).await?;
            let mut sandbox = sandbox_mutex.lock().await;
            let data = sandbox.get_data()?;
            let old_tasks = data.task_resources()?;
            update_resources(&req.sandbox_id, sandbox.deref_mut(), tasks, old_tasks).await?;
            data
        };

        data.extensions.insert("tasks".to_string(), tasks_any);
        self.sandboxer.update(&req.sandbox_id, data).await?;
        info!("update sandbox {} successfully", req.sandbox_id);
        Ok(Response::new(ControllerUpdateResponse {}))
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
        let (created_at, exited_at, address) = {
            let data = sandbox.get_data()?;
            (
                data.created_at.map(|x| x.into()),
                data.exited_at.map(|x| x.into()),
                data.task_address,
            )
        };
        debug!("status sandbox {} returns {:?}", req.sandbox_id, state);
        // TODO add verbose support
        return Ok(Response::new(ControllerStatusResponse {
            sandbox_id: req.sandbox_id.to_string(),
            pid,
            state,
            info: Default::default(),
            created_at,
            exited_at,
            extra: None,
            address: address,
            version: 2,
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

    async fn metrics(
        &self,
        _request: Request<ControllerMetricsRequest>,
    ) -> Result<Response<ControllerMetricsResponse>, Status> {
        let resp = ControllerMetricsResponse { metrics: None };
        return Ok(Response::new(resp));
    }
}

async fn update_resources<S>(
    sandbox_id: &str,
    sb: &mut S,
    tasks: TaskResources,
    old_tasks: TaskResources,
) -> Result<(), Status>
where
    S: Sandbox,
{
    for t in tasks.tasks.iter() {
        let mut exist = false;
        for ot in old_tasks.tasks.iter() {
            if t.task_id == ot.task_id {
                exist = true;
                update_process_resource(sandbox_id, sb, &t.task_id, &t.processes, &ot.processes)
                    .await?;
            }
        }
        if !exist {
            let container_data = ContainerData::new(t);
            info!(
                "append a container {:?} to sandbox {}",
                container_data, sandbox_id
            );
            let opt: ContainerOption = ContainerOption::new(container_data);
            sb.append_container(&t.task_id, opt).await?;
        }
    }
    for ot in old_tasks.tasks.iter() {
        let mut exist = false;
        for t in tasks.tasks.iter() {
            if ot.task_id == t.task_id {
                exist = true;
            }
        }
        if !exist {
            info!(
                "remove container {} from sandbox {}",
                ot.task_id, sandbox_id
            );
            sb.remove_container(&ot.task_id).await?;
        }
    }
    Ok(())
}

async fn update_process_resource<S>(
    sandbox_id: &str,
    sb: &mut S,
    task_id: &str,
    processes: &Vec<ProcessResource>,
    old_processes: &Vec<ProcessResource>,
) -> Result<(), Status>
where
    S: Sandbox,
{
    for p in processes.iter() {
        let mut exist = false;
        for op in old_processes.iter() {
            if p.exec_id == op.exec_id {
                exist = true;
            }
        }
        if !exist {
            let process_date = ProcessData::new(p);
            info!(
                "append a process {:?} to container {} of sandbox {}",
                process_date, task_id, sandbox_id
            );
            let container = sb.container(task_id).await?;
            let mut data = container.get_data()?;
            data.processes.push(process_date);
            let opt = ContainerOption::new(data);
            sb.update_container(task_id, opt).await?;
        }
    }
    for op in old_processes.iter() {
        let mut exist = false;
        for p in processes.iter() {
            if op.exec_id == p.exec_id {
                exist = true;
            }
        }
        if !exist {
            info!(
                "remove process {} from container {} of sandbox {}",
                op.exec_id, task_id, sandbox_id
            );
            let container = sb.container(task_id).await?;
            let mut data = container.get_data()?;
            data.processes.retain(|x| x.id != op.exec_id);
            let opt = ContainerOption::new(data);
            sb.update_container(task_id, opt).await?;
        }
    }
    Ok(())
}
