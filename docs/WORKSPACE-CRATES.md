# Workspace crates: what ships and what does not

`ci/shipped-crates-check.sh` (run by CI on every push) computes which crates
the shipped binaries (`patronus-cli`, `patronus-web`, `patronus-dashboard`)
depend on through path dependencies and fails if this page disagrees.

Linking is the floor, not the proof: a crate listed as linked can still have
parts nothing calls. Features are claimed in README.md only with a `[Cn]`
marker and a CI test (docs/claims-ledger.txt); nothing under "Not shipped" is
claimed anywhere.

## Linked into the shipped binaries
- `patronus-ai`
- `patronus-captiveportal`
- `patronus-cli`
- `patronus-cni`
- `patronus-config`
- `patronus-core`
- `patronus-dashboard`
- `patronus-ebpf`
- `patronus-firewall`
- `patronus-geodns`
- `patronus-gitops`
- `patronus-monitoring`
- `patronus-mpls`
- `patronus-network`
- `patronus-saas`
- `patronus-sdwan`
- `patronus-secrets`
- `patronus-web`

## Not shipped
Library-only or separate tools: no shipped binary contains them, the web UI
and dashboard cannot reach them, and the README makes no claim about them.
`patronus-install` (crate `patronus-installer`) is the installer program and
`patronus-operator` the Kubernetes operator; both are built and tested by
their own CI jobs. The rest are experiments and models.
- `patronus-advanced-ml`
- `patronus-ansible`
- `patronus-app-steering`
- `patronus-bench`
- `patronus-bgp`
- `patronus-capacity-plan`
- `patronus-control-plane`
- `patronus-diagnostics`
- `patronus-edge-computing`
- `patronus-gateway`
- `patronus-installer`
- `patronus-ml`
- `patronus-mlops`
- `patronus-multicloud`
- `patronus-multitenancy`
- `patronus-network-functions`
- `patronus-observability`
- `patronus-operator`
- `patronus-plugin`
- `patronus-proxy`
- `patronus-rl-optimizer`
- `patronus-security`
- `patronus-self-healing`
- `patronus-servicemesh`
- `patronus-traffic-eng`
- `patronus-tutorials`
- `patronus-vpn`
- `patronus-wan-opt`
