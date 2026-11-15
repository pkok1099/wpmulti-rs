//! Embedded HTTP Administration REST API and Prometheus metrics exposition.
//!
//! Exposes administrative endpoints (`/health`, `/status`, `/tunnels`, `/reload`, `/metrics`)
//! over an asynchronous HTTP/1.1 service.

pub mod metrics;
pub mod routes;
pub mod server;
#[cfg(test)]
pub mod tests;

pub use metrics::generate_prometheus_metrics;
pub use routes::{handle_admin_request, parse_http_request, HttpRequest, HttpResponse};
pub use server::AdminServer;
