//! eBPF Program Management

pub struct FirewallProgram {
    pub name: String,
    pub program_type: ProgramType,
    pub object_file: std::path::PathBuf,
}

pub enum ProgramType {
    Xdp,
    TcEgress,
    TcIngress,
    Cgroup,
}
