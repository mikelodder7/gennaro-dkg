use super::*;
use log::Metadata;

/// Does nothing, provided for convenience
#[derive(Debug)]
pub struct DefaultLogger {}

impl Log for DefaultLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, _record: &Record) {}

    fn flush(&self) {}
}
