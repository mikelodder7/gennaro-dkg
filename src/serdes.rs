pub(crate) mod prime_field {
    use blsful::inner_types::PrimeField;
    use serde::{
        de::{Error as DError, Unexpected, Visitor},
        Deserializer, Serializer,
    };
    use std::fmt::{self, Formatter};
    use std::marker::PhantomData;

    pub fn serialize<F: PrimeField, S: Serializer>(scalar: &F, s: S) -> Result<S::Ok, S::Error> {
        let v = scalar.to_repr();
        let vv = v.as_ref();
        if s.is_human_readable() {
            s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(vv))
        } else {
            s.serialize_bytes(v.as_ref())
        }
    }

    pub fn deserialize<'de, F: PrimeField, D: Deserializer<'de>>(d: D) -> Result<F, D::Error> {
        struct ScalarVisitor<F: PrimeField> {
            marker: PhantomData<F>,
        }

        impl<'de, F: PrimeField> Visitor<'de> for ScalarVisitor<F> {
            type Value = F;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a byte sequence")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DError,
            {
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(v.as_bytes())
                    .map_err(|_| DError::invalid_value(Unexpected::Str(v), &self))?;
                let mut repr = F::default().to_repr();
                let len = repr.as_ref().len();
                if bytes.len() != len {
                    return Err(DError::invalid_length(bytes.len(), &self));
                }
                repr.as_mut().copy_from_slice(bytes.as_slice());
                Option::<F>::from(F::from_repr(repr))
                    .ok_or(DError::custom("unable to convert to scalar".to_string()))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DError,
            {
                let mut repr = F::default().to_repr();
                let len = repr.as_ref().len();
                if v.len() != len {
                    return Err(DError::invalid_length(v.len(), &self));
                }
                repr.as_mut().copy_from_slice(v);
                Option::<F>::from(F::from_repr(repr))
                    .ok_or(DError::custom("unable to convert to scalar".to_string()))
            }
        }

        let vis = ScalarVisitor {
            marker: PhantomData::<F>,
        };
        if d.is_human_readable() {
            d.deserialize_str(vis)
        } else {
            d.deserialize_bytes(vis)
        }
    }
}

pub(crate) mod prime_field_map {
    use elliptic_curve::PrimeField;
    use serde::{
        de::{Error as DError, Visitor},
        ser::SerializeMap,
        Deserializer, Serializer,
    };
    use std::{
        collections::BTreeMap,
        fmt::{self, Formatter},
    };

    pub fn serialize<F: PrimeField, S: Serializer>(
        bmap: &BTreeMap<usize, F>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let is_human_readable = s.is_human_readable();
        let mut map = s.serialize_map(Some(bmap.len()))?;
        for (k, v) in bmap {
            map.serialize_key(k)?;
            let vv = v.to_repr();
            let rr = vv.as_ref();
            if is_human_readable {
                map.serialize_value(&data_encoding::BASE64URL_NOPAD.encode(rr))?;
            } else {
                map.serialize_value(rr)?;
            }
        }
        map.end()
    }

    pub fn deserialize<'de, F: PrimeField, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<usize, F>, D::Error> {
        if d.is_human_readable() {
            struct MapVisitor<F: PrimeField> {
                marker: std::marker::PhantomData<F>,
            }

            impl<'de, F: PrimeField> Visitor<'de> for MapVisitor<F> {
                type Value = BTreeMap<usize, F>;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a map of integers to strings")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut bmap = BTreeMap::new();
                    while let Some((k, v)) = map.next_entry::<usize, String>()? {
                        let bytes = data_encoding::BASE64URL_NOPAD
                            .decode(v.as_bytes())
                            .map_err(|_| {
                                DError::custom("unable to decode string to bytes".to_string())
                            })?;
                        let mut repr = F::default().to_repr();
                        let len = repr.as_ref().len();
                        if bytes.len() != len {
                            return Err(DError::custom(format!(
                                "invalid length, expected: {}, actual: {}",
                                len,
                                bytes.len()
                            )));
                        }
                        repr.as_mut().copy_from_slice(bytes.as_slice());
                        let pt = Option::<F>::from(F::from_repr(repr))
                            .ok_or(DError::custom("unable to convert to scalar".to_string()))?;
                        bmap.insert(k, pt);
                    }
                    Ok(bmap)
                }
            }

            let visitor = MapVisitor {
                marker: std::marker::PhantomData::<F>,
            };
            d.deserialize_map(visitor)
        } else {
            struct MapVisitor<F: PrimeField> {
                marker: std::marker::PhantomData<F>,
            }

            impl<'de, F: PrimeField> Visitor<'de> for MapVisitor<F> {
                type Value = BTreeMap<usize, F>;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a map of integers to byte sequences")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut bmap = BTreeMap::new();
                    while let Some((k, v)) = map.next_entry::<usize, &[u8]>()? {
                        let mut repr = F::default().to_repr();
                        let len = repr.as_ref().len();
                        if v.len() != len {
                            return Err(DError::custom(format!(
                                "invalid length, expected: {}, actual: {}",
                                len,
                                v.len()
                            )));
                        }
                        repr.as_mut().copy_from_slice(v);
                        let pt = Option::<F>::from(F::from_repr(repr))
                            .ok_or(DError::custom("unable to convert to scalar".to_string()))?;
                        bmap.insert(k, pt);
                    }
                    Ok(bmap)
                }
            }

            let visitor = MapVisitor {
                marker: std::marker::PhantomData::<F>,
            };
            d.deserialize_map(visitor)
        }
    }
}

pub(crate) mod group {
    use blsful::inner_types::{Group, GroupEncoding};
    use serde::de::{Error as DError, SeqAccess, Unexpected, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt::{self, Formatter};
    use std::marker::PhantomData;

    pub fn serialize<G: Group + GroupEncoding + Default, S: Serializer>(
        g: &G,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let v = g.to_bytes();
        let vv = v.as_ref();
        if s.is_human_readable() {
            s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(vv))
        } else {
            s.serialize_bytes(vv)
        }
    }

    pub fn deserialize<'de, G: Group + GroupEncoding + Default, D: Deserializer<'de>>(
        d: D,
    ) -> Result<G, D::Error> {
        struct GVisitor<G: Group + GroupEncoding + Default> {
            marker: PhantomData<G>,
        }

        impl<'de, G: Group + GroupEncoding + Default> Visitor<'de> for GVisitor<G> {
            type Value = G;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a base64 encoded string or tuple of bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DError,
            {
                let mut repr = G::Repr::default();
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(v.as_bytes())
                    .map_err(|_| DError::invalid_value(Unexpected::Str(v), &self))?;
                let len = repr.as_ref().len();
                if bytes.len() != len {
                    return Err(DError::invalid_length(bytes.len(), &self));
                }
                repr.as_mut().copy_from_slice(bytes.as_slice());
                Option::<G>::from(G::from_bytes(&repr)).ok_or(DError::custom(
                    "unable to convert to group element".to_string(),
                ))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DError,
            {
                let mut repr = G::Repr::default();
                let len = repr.as_ref().len();
                if v.len() != len {
                    return Err(DError::invalid_length(v.len(), &self));
                }
                repr.as_mut().copy_from_slice(v);
                Option::<G>::from(G::from_bytes(&repr)).ok_or(DError::custom(
                    "unable to convert to group element".to_string(),
                ))
            }
        }

        let visitor = GVisitor {
            marker: PhantomData,
        };
        if d.is_human_readable() {
            d.deserialize_str(visitor)
        } else {
            d.deserialize_bytes(visitor)
        }
    }
}

pub(crate) mod group_vec {
    use blsful::inner_types::{Group, GroupEncoding};
    use serde::de::Error as DError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<G: Group + GroupEncoding + Default, S: Serializer>(
        g: &[G],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let v = g.iter().map(|p| p.to_bytes()).collect::<Vec<G::Repr>>();
        if s.is_human_readable() {
            let vv = v
                .iter()
                .map(|b| data_encoding::BASE64URL_NOPAD.encode(b.as_ref()))
                .collect::<Vec<String>>();
            vv.serialize(s)
        } else {
            let bytes = g
                .iter()
                .flat_map(|p| p.to_bytes().as_ref().to_vec())
                .collect::<Vec<u8>>();
            s.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, G: Group + GroupEncoding + Default, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<G>, D::Error> {
        if d.is_human_readable() {
            let s = Vec::<String>::deserialize(d)?;
            let mut out = Vec::with_capacity(s.len());
            let mut repr = G::Repr::default();
            let len = repr.as_ref().len();
            for si in &s {
                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(si.as_bytes())
                    .map_err(|_| DError::custom("unable to decode string to bytes".to_string()))?;
                if bytes.len() != len {
                    return Err(DError::custom(format!(
                        "invalid length, expected: {}, actual: {}",
                        len,
                        bytes.len()
                    )));
                }
                repr.as_mut().copy_from_slice(bytes.as_slice());
                let pt = Option::<G>::from(G::from_bytes(&repr)).ok_or(DError::custom(
                    "unable to convert to group element".to_string(),
                ))?;
                out.push(pt);
            }
            Ok(out)
        } else {
            let bytes = Vec::<u8>::deserialize(d)?;
            let mut repr = G::Repr::default();
            let chunks = repr.as_ref().len();
            if bytes.len() % chunks != 0 {
                return Err(DError::custom(format!(
                    "invalid length, expected multiple of {}, actual: {}",
                    chunks,
                    bytes.len()
                )));
            }
            let mut out = Vec::with_capacity(bytes.len() / chunks);
            for chunk in bytes.chunks(chunks) {
                repr.as_mut().copy_from_slice(chunk);
                let pt = Option::<G>::from(G::from_bytes(&repr)).ok_or(DError::custom(
                    "unable to convert to group element".to_string(),
                ))?;
                out.push(pt);
            }
            Ok(out)
        }
    }
}
