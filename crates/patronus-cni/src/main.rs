use anyhow::Result;
use patronus_cni::{
    PatronusCniPlugin, CniConfig, CniCommand, CniRuntimeConfig,
    EbpfDatapath, NetworkPolicyController, ServiceMeshManager, ServiceMeshConfig,
};
use std::env;
use std::io::{self, Read};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse CNI command from environment
    let command = env::var("CNI_COMMAND").unwrap_or_else(|_| "VERSION".to_string());
    let command = match command.as_str() {
        "ADD" => CniCommand::Add,
        "DEL" => CniCommand::Del,
        "CHECK" => CniCommand::Check,
        "VERSION" => CniCommand::Version,
        _ => {
            error!("Unknown CNI command: {}", command);
            return Ok(());
        }
    };

    match command {
        CniCommand::Version => {
            // Return version info
            let version = PatronusCniPlugin::cmd_version();
            println!("{}", serde_json::to_string_pretty(&version)?);
            return Ok(());
        }

        CniCommand::Add | CniCommand::Del | CniCommand::Check => {
            // Read network configuration from stdin
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;

            let config: CniConfig = serde_json::from_str(&buffer)?;

            // Parse runtime config from environment
            let runtime = CniRuntimeConfig {
                container_id: env::var("CNI_CONTAINERID").unwrap_or_default(),
                netns: env::var("CNI_NETNS").unwrap_or_default(),
                ifname: env::var("CNI_IFNAME").unwrap_or_default(),
                args: env::var("CNI_ARGS").ok(),
                path: env::var("CNI_PATH").unwrap_or_default(),
            };

            let plugin = PatronusCniPlugin::new(config.clone(), runtime);

            match command {
                CniCommand::Add => {
                    info!("Executing CNI ADD");

                    // Execute CNI ADD
                    match plugin.cmd_add() {
                        Ok(result) => {
                            // Initialize eBPF datapath
                            let datapath = Arc::new(EbpfDatapath::new());

                            // Create pod endpoint
                            let endpoint = patronus_cni::PodEndpoint {
                                pod_name: "pod".to_string(), // Would be extracted from args
                                namespace: "default".to_string(), // Would be extracted from args
                                pod_ip: result.ips[0].address.parse().unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
                                host_veth: result.interfaces[0].name.clone(),
                                container_id: plugin.runtime.container_id.clone(),
                            };

                            // Attach eBPF programs
                            if let Err(e) = datapath.attach_programs(&endpoint).await {
                                error!("Failed to attach eBPF programs: {}", e);
                            }

                            // Return result
                            println!("{}", serde_json::to_string_pretty(&result)?);
                        }
                        Err(e) => {
                            error!("CNI ADD failed: {}", e);
                            let err = patronus_cni::CniError {
                                cni_version: patronus_cni::cni_plugin::CNI_VERSION.to_string(),
                                code: 100,
                                msg: format!("ADD failed: {}", e),
                                details: None,
                            };
                            println!("{}", serde_json::to_string_pretty(&err)?);
                            std::process::exit(1);
                        }
                    }
                }

                CniCommand::Del => {
                    info!("Executing CNI DEL");

                    // Execute CNI DEL
                    match plugin.cmd_del() {
                        Ok(()) => {
                            // Detach eBPF programs
                            let datapath = Arc::new(EbpfDatapath::new());
                            if let Err(e) = datapath.detach_programs(&plugin.runtime.container_id).await {
                                error!("Failed to detach eBPF programs: {}", e);
                            }

                            println!("{{}}"); // Empty success response
                        }
                        Err(e) => {
                            error!("CNI DEL failed: {}", e);
                            let err = patronus_cni::CniError {
                                cni_version: patronus_cni::cni_plugin::CNI_VERSION.to_string(),
                                code: 101,
                                msg: format!("DEL failed: {}", e),
                                details: None,
                            };
                            println!("{}", serde_json::to_string_pretty(&err)?);
                            std::process::exit(1);
                        }
                    }
                }

                CniCommand::Check => {
                    info!("Executing CNI CHECK");

                    match plugin.cmd_check() {
                        Ok(()) => {
                            println!("{{}}"); // Empty success response
                        }
                        Err(e) => {
                            error!("CNI CHECK failed: {}", e);
                            let err = patronus_cni::CniError {
                                cni_version: patronus_cni::cni_plugin::CNI_VERSION.to_string(),
                                code: 102,
                                msg: format!("CHECK failed: {}", e),
                                details: None,
                            };
                            println!("{}", serde_json::to_string_pretty(&err)?);
                            std::process::exit(1);
                        }
                    }
                }

                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

/// Standalone daemon mode for running policy controller and service mesh
#[allow(dead_code)]
async fn run_daemon() -> Result<()> {
    info!("Starting Patronus CNI daemon");

    // Initialize components
    let datapath = Arc::new(EbpfDatapath::new());
    let policy_controller = Arc::new(NetworkPolicyController::new(Arc::clone(&datapath)).await?);
    let service_mesh = Arc::new(ServiceMeshManager::new(ServiceMeshConfig::default()));

    // Start policy controller
    let policy_task = {
        let controller = Arc::clone(&policy_controller);
        tokio::spawn(async move {
            if let Err(e) = controller.start().await {
                error!("Policy controller failed: {}", e);
            }
        })
    };

    info!("Patronus CNI daemon started");

    // Wait for tasks
    policy_task.await?;

    Ok(())
}
