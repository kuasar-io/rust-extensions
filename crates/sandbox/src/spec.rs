use std::collections::HashMap;

use anyhow::anyhow;
use serde::Deserialize;
use serde::Serialize;

use crate::error::Result;
use prost_types::Any;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct JsonSpec {
    #[serde(rename = "ociVersion")]
    pub version: String,
    #[serde(default)]
    pub process: Option<Process>,
    #[serde(default)]
    pub root: Option<Root>,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub hooks: Option<Hooks>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    pub linux: Option<Linux>,
    #[serde(default)]
    pub vm: Option<VM>,
    #[serde(default)]
    pub solaris: Option<Solaris>,
    #[serde(default)]
    pub windows: Option<Windows>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Root {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Mount {
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Linux {
    #[serde(rename = "uidMappings", default)]
    pub uid_mappings: Vec<LinuxIDMapping>,
    #[serde(rename = "gidMappings", default)]
    pub gid_mappings: Vec<LinuxIDMapping>,
    #[serde(default)]
    pub sysctl: HashMap<String, String>,
    pub resources: Option<LinuxResources>,
    #[serde(rename = "cgroupsPath", default)]
    pub cgroups_path: String,
    #[serde(default)]
    pub namespaces: Vec<LinuxNamespace>,
    #[serde(default)]
    pub devices: Vec<LinuxDevice>,
    #[serde(default)]
    pub seccomp: Option<LinuxSeccomp>,
    #[serde(
        rename = "rootfsPropagation",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub rootfs_propagation: String,
    #[serde(rename = "maskedPaths", default)]
    pub masked_path: Vec<String>,
    #[serde(rename = "readonlyPaths", default)]
    pub readonly_path: Vec<String>,
    #[serde(
        rename = "mountLabel",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub mount_label: String,
    #[serde(rename = "intelRdt")]
    pub intel_rdt: Option<LinuxIntelRdt>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxIDMapping {
    #[serde(rename = "containerID", default)]
    pub container_id: u32,
    #[serde(rename = "hostID", default)]
    pub host_id: u32,
    #[serde(default)]
    pub sieze: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxResources {
    #[serde(default)]
    pub devices: Vec<LinuxDeviceCgroup>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub memory: Option<LinuxMemory>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu: Option<LinuxCPU>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pids: Option<LinuxPids>,
    #[serde(rename = "blockIO", skip_serializing_if = "Option::is_none")]
    pub block_io: Option<LinuxBlockIO>,
    #[serde(rename = "hugepageLimits", default)]
    pub hugepage_limits: Vec<LinuxHugepageLimit>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<LinuxNetwork>,
    #[serde(default)]
    pub rdma: HashMap<String, LinuxRdma>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub files: Option<Files>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxDeviceCgroup {
    #[serde(default)]
    pub allow: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub major: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub minor: Option<i64>,
    #[serde(default)]
    pub access: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxMemory {
    pub limit: Option<u64>,
    pub reservation: Option<u64>,
    pub swap: Option<u64>,
    pub kernel: Option<u64>,
    #[serde(rename = "kernelTCP")]
    pub kernel_tcp: Option<u64>,
    pub swappiness: Option<u64>,
    #[serde(rename = "disableOOMKiller")]
    pub disable_oom_killer: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxCPU {
    pub shares: Option<u64>,
    pub quota: Option<i64>,
    pub period: Option<u64>,
    #[serde(rename = "realtimeRuntime")]
    pub realtime_runtime: Option<i64>,
    #[serde(rename = "realtimePeriod")]
    pub realtime_period: Option<u64>,
    #[serde(default)]
    pub cpus: String,
    #[serde(default)]
    pub mems: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxPids {
    #[serde(default)]
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxBlockIO {
    #[serde(default)]
    pub weight: Option<u16>,
    #[serde(rename = "leafWeight", default)]
    pub leaf_weight: Option<u16>,
    #[serde(rename = "weightDevice", default)]
    pub weight_device: Vec<LinuxWeightDevice>,
    #[serde(rename = "throttleReadBpsDevice", default)]
    pub throttle_read_bps_device: Vec<LinuxThrottleDevice>,
    #[serde(rename = "throttleWriteBpsDevice", default)]
    pub throttle_write_bps_device: Vec<LinuxThrottleDevice>,
    #[serde(rename = "throttleReadIOPSDevice", default)]
    pub throttle_read_iops_device: Vec<LinuxThrottleDevice>,
    #[serde(rename = "throttleWriteIOPSDevice", default)]
    pub throttle_write_iobs_device: Vec<LinuxThrottleDevice>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxWeightDevice {
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
    pub weight: Option<u16>,
    #[serde(rename = "leafWeight")]
    pub leaf_weight: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxThrottleDevice {
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
    #[serde(default)]
    pub rate: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxHugepageLimit {
    #[serde(rename = "pageSize", default)]
    pub page_size: String,
    #[serde(default)]
    pub limit: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxNetwork {
    #[serde(rename = "classID", default)]
    pub class_id: Option<u32>,
    #[serde(default)]
    pub priorities: Vec<LinuxInterfacePriority>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxInterfacePriority {
    #[serde(rename = "classID", default)]
    pub name: String,
    #[serde(default)]
    pub priority: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxRdma {
    #[serde(rename = "hcaHandles", default)]
    pub hca_handles: Option<u32>,
    #[serde(rename = "hcaObjects", default)]
    pub hca_objects: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Files {
    pub limit: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxNamespace {
    #[serde(default)]
    pub r#type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxDevice {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
    #[serde(rename = "fileMode")]
    pub file_mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxSeccomp {
    #[serde(rename = "defaultAction", default)]
    pub default_action: String,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub syscalls: Vec<LinuxSyscall>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxSyscall {
    pub names: Vec<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub args: Vec<LinuxSeccompArg>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxSeccompArg {
    #[serde(default)]
    pub index: u32,
    #[serde(default)]
    pub value: u64,
    #[serde(rename = "valueTwo", default)]
    pub value_two: u64,
    #[serde(default)]
    pub op: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxIntelRdt {
    #[serde(rename = "closID", default)]
    pub clos_id: String,
    #[serde(rename = "l3CacheSchema", default)]
    pub l3cache_scheme: String,
    #[serde(rename = "memBwSchema", default)]
    pub membw_scheme: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VM {
    #[serde(default)]
    pub hypervisor: VMHypervisor,
    #[serde(default)]
    pub kernel: VMKernel,
    #[serde(default)]
    pub image: VMImage,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Windows {
    #[serde(default)]
    pub dummy: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Solaris {
    #[serde(default)]
    pub dummy: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VMHypervisor {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub parameters: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VMKernel {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub parameters: Vec<String>,
    #[serde(default)]
    pub initrd: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VMImage {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub format: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Process {
    #[serde(default)]
    pub terminal: bool,
    pub console_size: Option<Box>,
    #[serde(default)]
    pub user: User,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(rename = "commandLine", default)]
    pub command_line: String,
    #[serde(default)]
    pub env: Vec<String>,
    pub cwd: String,
    pub capabilities: Option<LinuxCapabilities>,
    #[serde(default)]
    pub rlimits: Vec<POSIXRlimit>,
    #[serde(rename = "noNewPrivileges", default)]
    pub no_new_privileges: bool,
    #[serde(
        rename = "apparmorProfile",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub apparmor_profile: String,
    #[serde(rename = "oomScoreAdj")]
    pub oom_score_adj: Option<i32>,
    #[serde(rename = "selinuxLabel", default)]
    pub selinux_label: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Box {
    pub height: u32,
    pub width: u32,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct User {
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default)]
    pub umask: u32,
    #[serde(rename = "additionalGids", default)]
    pub additional_gids: Vec<u32>,
    #[serde(rename = "username", default)]
    pub user_name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxCapabilities {
    #[serde(default)]
    pub bounding: Vec<String>,
    #[serde(default)]
    pub effective: Vec<String>,
    #[serde(default)]
    pub inheritable: Vec<String>,
    #[serde(default)]
    pub permitted: Vec<String>,
    #[serde(default)]
    pub ambient: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct POSIXRlimit {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub hard: u64,
    #[serde(default)]
    pub soft: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Hooks {
    #[serde(default)]
    pub prestart: Vec<Hook>,
    #[serde(default)]
    pub poststart: Vec<Hook>,
    #[serde(default)]
    pub poststop: Vec<Hook>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Hook {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub timeout: i64,
}

impl Process {
    pub fn new() -> Process {
        Process {
            terminal: false,
            console_size: None,
            user: User {
                uid: 0,
                gid: 0,
                umask: 0,
                additional_gids: vec![],
                user_name: "".to_string(),
            },
            args: vec![],
            command_line: "".to_string(),
            env: vec![],
            cwd: "".to_string(),
            capabilities: None,
            rlimits: vec![],
            no_new_privileges: false,
            apparmor_profile: "".to_string(),
            oom_score_adj: None,
            selinux_label: "".to_string(),
        }
    }
}

const CRI_CONTAINERD_CONTAINER_TYPE_KEY: &'static str = "io.kubernetes.cri.container-type";
const CRIO_CONTAINER_TYPE_KEY: &'static str = "io.kubernetes.cri-o.ContainerType";
const DOCKERSHIM_CONTAINER_TYPE_KEY: &'static str = "io.kubernetes.docker.type";

const CONTAINER_TYPE_SANDBOX: &'static str = "sandbox";
const CONTAINER_TYPE_PODSANDBOX: &'static str = "podsandbox";
const CONTAINER_TYPE_CONTAINER: &'static str = "container";

const CRI_CONTAINERD_SANDBOX_ID_KEY: &'static str = "io.kubernetes.cri.sandbox-id";
const CRIO_SANDBOX_ID_KEY: &'static str = "io.kubernetes.cri-o.SandboxID";
const DOCKERSHIM_SANDBOX_ID_KEY: &'static str = "io.kubernetes.sandbox.id";

#[derive(Debug)]
pub enum ContainerType {
    Sandbox,
    Container,
    Unknown,
}

impl ContainerType {
    pub fn from_annotations(annotations: &HashMap<String, String>) -> ContainerType {
        for (k, v) in annotations.iter() {
            match k.as_str() {
                CRI_CONTAINERD_CONTAINER_TYPE_KEY => return Self::from(v.as_str()),
                CRIO_CONTAINER_TYPE_KEY => return Self::from(v.as_str()),
                DOCKERSHIM_CONTAINER_TYPE_KEY => return Self::from(v.as_str()),
                _ => {}
            }
        }
        return Self::Sandbox;
    }
}

impl From<&str> for ContainerType {
    fn from(s: &str) -> Self {
        match s {
            CONTAINER_TYPE_SANDBOX => Self::Sandbox,
            CONTAINER_TYPE_PODSANDBOX => Self::Sandbox,
            CONTAINER_TYPE_CONTAINER => Self::Container,
            _ => Self::Unknown,
        }
    }
}

pub fn get_sandbox_id(annotations: &HashMap<String, String>) -> Option<&str> {
    let group_labels: [&str; 3] = [
        CRI_CONTAINERD_SANDBOX_ID_KEY,
        CRIO_SANDBOX_ID_KEY,
        DOCKERSHIM_SANDBOX_ID_KEY,
    ];
    for group in group_labels.iter() {
        if annotations.contains_key(*group) {
            return annotations.get(*group).map(|v| v.as_str());
        }
    }
    None
}

pub fn to_any(spec: &JsonSpec) -> Result<Any> {
    let spec_vec =
        serde_json::to_vec(spec).map_err(|e| anyhow!("failed to parse sepc to json, {}", e))?;
    Ok(Any {
        type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
        value: spec_vec,
    })
}

impl From<&crate::types::Mount> for Mount {
    fn from(m: &crate::types::Mount) -> Self {
        return Self {
            destination: "".to_string(),
            r#type: m.r#type.to_string(),
            source: m.source.to_string(),
            options: m.options.clone(),
        };
    }
}

impl From<&Mount> for crate::types::Mount {
    fn from(m: &Mount) -> Self {
        return Self {
            r#type: m.r#type.to_string(),
            source: m.source.to_string(),
            target: m.destination.to_string(),
            options: m.options.clone(),
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::spec::{Box, JsonSpec, Process, User};

    #[test]
    fn test_process() {
        let p = Process {
            terminal: true,
            console_size: Some(Box {
                height: 1,
                width: 2,
            }),
            user: User {
                uid: 1000,
                gid: 1000,
                umask: 0,
                additional_gids: vec![2000],
                user_name: "myusername".to_string(),
            },
            args: vec!["--arg1".to_string(), "arg1".to_string()],
            command_line: "bash".to_string(),
            env: vec!["HOST=myhost".to_string()],
            cwd: "/tmp/1".to_string(),
            capabilities: None,
            rlimits: vec![],
            no_new_privileges: false,
            apparmor_profile: "".to_string(),
            oom_score_adj: None,
            selinux_label: "".to_string(),
        };

        let result = serde_json::to_string(&p).unwrap();
        let p2 = serde_json::from_str::<Process>(&result).unwrap();
        assert_eq!(p.terminal, p2.terminal);
        assert_eq!(p.oom_score_adj, p2.oom_score_adj);
        let console_size = p2.console_size.unwrap();
        assert_eq!(console_size.width, 2);
        assert_eq!(console_size.height, 1);
        let s = "{\"terminal\":true,\"console_size\":{\"height\":1,\"width\":2},\"user\":{\"uid\":1000,\"gid\":1000,\"umask\":0,\"additionalGids\":[2000],\"username\":\"myusername\"},\"args\":[\"--arg1\",\"arg1\"],\"commandLine\":\"bash\",\"env\":[\"HOST=myhost\"],\"cwd\":\"/tmp/1\",\"capabilities\":null,\"rlimits\":[],\"noNewPrivileges\":false,\"selinuxLabel\":\"\"}";
        let p3 = serde_json::from_str::<Process>(s).unwrap();
        assert_eq!(p3.apparmor_profile, "");
        assert_eq!(p3.oom_score_adj, None);
    }

    #[test]
    fn test_spec() {
        let spec_str = r#"
{
  "ociVersion": "1.0.2-dev",
  "process": {
    "user": {
      "uid": 0,
      "gid": 0
    },
    "args": [
      "/pause"
    ],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "cwd": "/",
    "capabilities": {
      "bounding": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "effective": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "inheritable": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ]
    },
    "noNewPrivileges": true,
    "oomScoreAdj": -998
  },
  "root": {
    "path": "rootfs",
    "readonly": true
  },
  "mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": [
        "nosuid",
        "strictatime",
        "mode=755",
        "size=65536k"
      ]
    },
    {
      "destination": "/dev/pts",
      "type": "devpts",
      "source": "devpts",
      "options": [
        "nosuid",
        "noexec",
        "newinstance",
        "ptmxmode=0666",
        "mode=0620",
        "gid=5"
      ]
    },
    {
      "destination": "/dev/shm",
      "type": "tmpfs",
      "source": "shm",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "mode=1777",
        "size=65536k"
      ]
    },
    {
      "destination": "/dev/mqueue",
      "type": "mqueue",
      "source": "mqueue",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "ro"
      ]
    },
    {
      "destination": "/dev/shm",
      "type": "bind",
      "source": "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/de9e81f4e553d095154fb34ddcb9f8812c507cc142bc3752979dfcc56a976859/shm",
      "options": [
        "rbind",
        "ro"
      ]
    },
    {
      "destination": "/etc/resolv.conf",
      "type": "bind",
      "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/de9e81f4e553d095154fb34ddcb9f8812c507cc142bc3752979dfcc56a976859/resolv.conf",
      "options": [
        "rbind",
        "ro"
      ]
    }
  ],
  "annotations": {
    "io.kubernetes.cri.container-type": "sandbox",
    "io.kubernetes.cri.sandbox-id": "de9e81f4e553d095154fb34ddcb9f8812c507cc142bc3752979dfcc56a976859",
    "io.kubernetes.cri.sandbox-log-directory": ""
  },
  "linux": {
    "resources": {
      "devices": [
        {
          "allow": false,
          "access": "rwm"
        }
      ],
      "cpu": {
        "shares": 2
      }
    },
    "cgroupsPath": "/k8s.io/de9e81f4e553d095154fb34ddcb9f8812c507cc142bc3752979dfcc56a976859",
    "namespaces": [
      {
        "type": "pid"
      },
      {
        "type": "ipc"
      },
      {
        "type": "mount"
      }
    ],
    "maskedPaths": [
      "/proc/acpi",
      "/proc/asound",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/sys/firmware",
      "/proc/scsi"
    ],
    "readonlyPaths": [
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ]
  }
}"#;
        let spec = serde_json::from_str::<JsonSpec>(&spec_str).unwrap();
        assert!(spec.vm.is_none());
        assert_eq!(
            spec.linux.unwrap().cgroups_path,
            "/k8s.io/de9e81f4e553d095154fb34ddcb9f8812c507cc142bc3752979dfcc56a976859"
        );
    }
}
