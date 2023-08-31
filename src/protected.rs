use super::*;
use serde::{ser, Deserialize, Deserializer, Serialize, Serializer};
use soteria_rs::Protected;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

pub fn serialize<S: Serializer>(
    input: &BTreeMap<usize, Arc<RefCell<Protected>>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let mut placeholder = BTreeMap::new();
    for (key, value) in input {
        let mut p = value.borrow_mut();
        let u = p
            .unprotect()
            .ok_or_else(|| ser::Error::custom("memory tampered"))?;
        let val = u
            .serde::<Round1P2PData>()
            .map_err(|e| ser::Error::custom(e.to_string()))?;
        placeholder.insert(*key, val);
    }

    placeholder.serialize(s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<usize, Arc<RefCell<Protected>>>, D::Error> {
    let input = BTreeMap::<usize, Round1P2PData>::deserialize(d)?;
    let mut placeholder = BTreeMap::new();
    for (key, value) in &input {
        let val = Arc::new(RefCell::new(Protected::serde(value).unwrap()));
        placeholder.insert(*key, val);
    }
    Ok(placeholder)
}
