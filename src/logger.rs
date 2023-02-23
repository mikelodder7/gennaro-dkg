use super::*;
use log::Metadata;
use serde::{Deserialize, Serialize};

/// Does nothing, provided for convenience
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct DefaultLogger {}

impl Log for DefaultLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, _record: &Record) {}

    fn flush(&self) {}
}
