use std::collections::HashMap;
use std::time::SystemTime;

use log::warn;
use prost::Message;
use serde::Deserialize;
use serde::Serialize;
use tonic::Status;

use crate::spec::{JsonSpec, Mount, Process};
use crate::PodSandboxConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxData {
    pub id: String,
    pub spec: Option<JsonSpec>,
    pub config: Option<PodSandboxConfig>,
    pub netns: String,
    pub task_address: String,
    pub labels: HashMap<String, String>,
    pub created_at: Option<SystemTime>,
    pub started_at: Option<SystemTime>,
    pub exited_at: Option<SystemTime>,
    pub extensions: HashMap<String, Any>,
}

impl SandboxData {
    pub fn new(req: &crate::api::sandbox::v1::ControllerCreateRequest) -> Self {
        let config: Option<PodSandboxConfig> = req.options.as_ref().and_then(|x| {
            match PodSandboxConfig::decode(&*x.value) {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!(
                        "failed to parse container spec {} of {} from request, {}",
                        String::from_utf8_lossy(x.value.as_slice()),
                        req.sandbox_id,
                        e
                    );
                    None
                }
            }
            // match serde_json::from_slice::<PodSandboxConfig>(x.value.as_slice()) {
            //     Ok(s) => Some(s),
            //     Err(e) => {
            //         warn!(
            //             "failed to parse container spec {} of {} from request, {}",
            //             String::from_utf8_lossy(x.value.as_slice()),req.sandbox_id, e
            //         );
            //         None
            //     }
            // }
        });
        let extensions = if let Some(sb) = &req.sandbox {
            sb.extensions
                .iter()
                .map(|(k, v)| (k.clone(), Any::from(v)))
                .collect()
        } else {
            Default::default()
        };
        Self {
            id: req.sandbox_id.to_string(),
            spec: None,
            config,
            task_address: "".to_string(),
            labels: Default::default(),
            created_at: Some(SystemTime::now()),
            netns: req.netns_path.to_string(),
            started_at: None,
            exited_at: None,
            extensions: extensions,
        }
    }

    pub fn task_resources(&self) -> Result<TaskResources, Status> {
        let mut tasks = TaskResources { tasks: vec![] };
        if let Some(a) = self.extensions.get("tasks") {
            tasks = serde_json::from_slice(a.value.as_slice()).map_err(|e| {
                Status::invalid_argument(format!("failed to unmarshal old tasks {}", e))
            })?;
        }
        Ok(tasks)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

impl From<prost_types::Timestamp> for Timestamp {
    fn from(from: prost_types::Timestamp) -> Self {
        Self {
            seconds: from.seconds,
            nanos: from.nanos,
        }
    }
}

impl From<Timestamp> for prost_types::Timestamp {
    fn from(from: Timestamp) -> Self {
        Self {
            seconds: from.seconds,
            nanos: from.nanos,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerData {
    pub id: String,
    pub spec: Option<JsonSpec>,
    pub rootfs: Vec<Mount>,
    pub io: Option<Io>,
    pub processes: Vec<ProcessData>,
    pub bundle: String,
    pub labels: HashMap<String, String>,
    pub extensions: HashMap<String, Any>,
}

impl ContainerData {
    pub fn new(req: &crate::data::TaskResource) -> Self {
        Self {
            id: req.task_id.to_string(),
            spec: req.spec.clone(),
            rootfs: req.rootfs.clone(),
            io: Some(Io {
                stdin: req.stdin.to_string(),
                stdout: req.stdout.to_string(),
                stderr: req.stderr.to_string(),
                terminal: false,
            }),
            processes: vec![],
            bundle: "".to_string(),
            labels: Default::default(),
            extensions: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Io {
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub terminal: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessData {
    pub id: String,
    pub io: Option<Io>,
    pub process: Option<Process>,
    pub extra: HashMap<String, Any>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TaskResources {
    #[serde(default)]
    pub tasks: Vec<TaskResource>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TaskResource {
    #[serde(default)]
    pub task_id: String,
    #[serde(default)]
    pub spec: Option<JsonSpec>,
    #[serde(default)]
    pub rootfs: Vec<Mount>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub processes: Vec<ProcessResource>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProcessResource {
    #[serde(default)]
    pub exec_id: String,
    #[serde(default)]
    pub spec: Option<Process>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

impl ProcessData {
    pub fn new(req: &crate::data::ProcessResource) -> Self {
        Self {
            id: req.exec_id.to_string(),
            io: Some(Io {
                stdin: req.stdin.to_string(),
                stdout: req.stdout.to_string(),
                stderr: req.stderr.to_string(),
                terminal: false,
            }),
            process: req.spec.clone(),
            extra: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Any {
    pub type_url: String,
    #[serde(with = "crate::base64")]
    pub value: Vec<u8>,
}

impl From<prost_types::Any> for Any {
    fn from(proto: prost_types::Any) -> Self {
        Self {
            type_url: proto.type_url,
            value: proto.value,
        }
    }
}

impl From<&prost_types::Any> for Any {
    fn from(proto: &prost_types::Any) -> Self {
        Self {
            type_url: proto.type_url.clone(),
            value: proto.value.clone(),
        }
    }
}

impl From<Any> for prost_types::Any {
    fn from(any: Any) -> Self {
        Self {
            type_url: any.type_url,
            value: any.value,
        }
    }
}
