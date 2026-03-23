pub mod sbom;
pub mod vulnerability;

// Convenience re-exports so engine code can write `models::Component` etc.
pub use sbom::{Component, SbomDocument};
pub use vulnerability::{Severity, VexDocument, VexStatement, VexStatus, Vulnerability};
