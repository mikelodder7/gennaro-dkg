use super::*;

/// The parameters used by the DKG participants.
/// This must be the same for all of them otherwise the protocol
/// will abort.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Parameters<G: Group + GroupEncoding + Default> {
    pub(crate) threshold: usize,
    pub(crate) limit: usize,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    pub(crate) message_generator: G,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    pub(crate) blinder_generator: G,
}

impl<G: Group + GroupEncoding + Default> Default for Parameters<G> {
    fn default() -> Self {
        Self {
            threshold: 0,
            limit: 0,
            message_generator: G::identity(),
            blinder_generator: G::identity(),
        }
    }
}

impl<G: Group + GroupEncoding + Default> Parameters<G> {
    /// Create regular parameters with the message_generator as the default generator
    /// and a random blinder_generator
    pub fn new(threshold: NonZeroUsize, limit: NonZeroUsize) -> Self {
        let message_generator = G::generator();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&message_generator.to_bytes().as_ref()[0..32]);
        let rng = rand_chacha::ChaChaRng::from_seed(seed);
        Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator: G::generator(),
            blinder_generator: G::random(rng),
        }
    }

    /// Use the provided parameters
    pub fn with_generators(
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
        message_generator: G,
        blinder_generator: G,
    ) -> Self {
        Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator,
            blinder_generator,
        }
    }
}
