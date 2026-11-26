//! Configuration importers shared by `patronus import pfsense` / `patronus import-uci`
//! (patronus-cli) and the web UI's import page (patronus-web, feature `import`).
//!
//! Each importer works in two steps: `build_plan` reads the foreign configuration offline
//! and maps it to Patronus resources (anything that does not map is listed, never dropped),
//! `apply` writes the plan into the config store. Neither touches the running system: the
//! normal apply path (`patronus apply`, the web UI's Apply) renders the result.

pub mod pfsense;
pub mod uci;
