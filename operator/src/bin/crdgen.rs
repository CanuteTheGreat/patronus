//! CRD Generator - Generates Kubernetes CRD YAML from Rust types

use kube::CustomResourceExt;
use patronus_operator::crd::{policy::Policy, site::Site};

fn main() {
    // Generate Site CRD
    let site_crd = Site::crd();
    println!("---");
    println!("# Site CRD");
    println!("{}", serde_yaml::to_string(&site_crd).unwrap());

    // Generate Policy CRD
    let policy_crd = Policy::crd();
    println!("---");
    println!("# Policy CRD");
    println!("{}", serde_yaml::to_string(&policy_crd).unwrap());
}
