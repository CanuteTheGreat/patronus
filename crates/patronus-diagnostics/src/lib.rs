//! Diagnostic Tools
//!
//! Network troubleshooting and diagnostic utilities.

pub mod packet_capture;
pub mod tools;

pub use packet_capture::{
    PacketCaptureManager, CaptureConfig, CaptureSession, CaptureStats,
    CaptureFormat, CaptureInfo, PacketDetails, BpfFilters,
};

pub use tools::{
    DiagnosticTools, PingResult, TracerouteResult, TracerouteHop,
    DnsLookupResult, DnsRecord, PortTestResult, ArpEntry, NdpEntry,
    RouteEntry, SocketEntry, FirewallState, SystemActivity, ProcessInfo,
};
