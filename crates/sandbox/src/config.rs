use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PodSandboxConfig {
    pub metadata: PodSandboxMetadata,
    pub hostname: String,
    pub log_directory: String,
    pub dns_config: DNSConfig,
    pub port_mappings: Vec<PortMapping>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub linux: Option<LinuxPodSandboxConfig>,
    pub windows: Option<WindowsPodSandboxConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PodSandboxMetadata {
    pub name: String,
    pub uid: String,
    pub namespace: String,
    pub attempt: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DNSConfig {
    pub servers: Vec<String>,
    pub searches: Vec<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PortMapping {
    pub protocol: i32,
    pub container_port: i32,
    pub host_port: i32,
    pub host_ip: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxPodSandboxConfig {
    pub cgroup_parent: String,
    pub security_context: Option<LinuxSecurityContext>,
    pub sysctls: HashMap<String, String>,
    pub overhead: Option<LinuxContainerResources>,
    pub resources: Option<LinuxContainerResources>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxSecurityContext {
    namespace_options: Option<NamespaceOption>,
    selinux_options: Option<SELinuxOption>,
    run_as_user: Option<Int64Value>,
    run_as_group: Option<Int64Value>,
    readonly_rootfs: bool,
    supplemental_groups: Vec<i32>,
    privileged: bool,
    seccomp: Option<SecurityProfile>,
    apparmor: Option<SecurityProfile>,
    seccomp_profile_path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NamespaceOption {
    pub network: i32,
    pub pid: i32,
    pub target_id: i32,
    pub userns_options: Option<UserNamespace>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserNamespace {
    pub mode: i32,
    pub uids: Vec<IDMapping>,
    pub gids: Vec<IDMapping>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IDMapping {
    pub host_id: u32,
    pub container_id: u32,
    pub length: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SELinuxOption {
    pub user: String,
    pub role: String,
    pub r#type: String,
    pub level: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Int64Value {
    pub value: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityProfile {
    pub profile_type: i32,
    pub localhost_ref: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinuxContainerResources {
    pub cpu_period: i64,
    pub cpu_quota: i64,
    pub cpu_shares: i64,
    pub memory_limit_in_bytes: i64,
    pub oom_score_adj: i64,
    pub cpuset_cpus: String,
    pub cpuset_mems: String,
    pub hugepage_limits: Vec<HugepageLimit>,
    pub unified: HashMap<String, String>,
    pub memory_swap_limit_in_bytes: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HugepageLimit {
    pub page_size: String,
    pub limit: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WindowsPodSandboxConfig {
    pub security_context: Option<WindowsSandboxSecurityContext>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WindowsSandboxSecurityContext {
    pub run_as_username: String,
    pub credential_spec: String,
    pub host_process: bool,
    pub namespace_options: Option<WindowsNamespaceOption>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WindowsNamespaceOption {
    pub network: i32,
}
