use serde::{ser, Deserialize, Deserializer, Serialize, Serializer};
use soteria_rs::Protected;
use std::sync::{Arc, Mutex};

pub fn serialize<S: Serializer>(input: &Arc<Mutex<Protected>>, s: S) -> Result<S::Ok, S::Error> {
    let mut protected = input
        .lock()
        .map_err(|_e| ser::Error::custom("unable to acquire lock".to_string()))?;
    let unprotected = protected
        .unprotect()
        .ok_or_else(|| ser::Error::custom("invalid secret"))?;
    unprotected.as_ref().serialize(s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Arc<Mutex<Protected>>, D::Error> {
    let input = Vec::<u8>::deserialize(d)?;
    Ok(Arc::new(Mutex::new(Protected::new(input.as_slice()))))
}
