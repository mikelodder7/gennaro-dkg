use super::*;
use crate::serdes::*;

use vsss_rs::{ParticipantNumberGenerator, SequentialParticipantNumberGenerator};

/// The parameters used by the DKG participants.
/// This must be the same for all of them otherwise the protocol
/// will abort.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Parameters<
    G: Group + GroupEncoding + Default,
    P: ParticipantNumberGenerator<G::Scalar> + Default,
> {
    pub(crate) threshold: usize,
    pub(crate) limit: usize,
    #[serde(with = "group")]
    pub(crate) message_generator: G,
    #[serde(with = "group")]
    pub(crate) blinder_generator: G,
    pub(crate) participant_number_generator: P,
}

impl<G: Group + GroupEncoding + Default, P: ParticipantNumberGenerator<G::Scalar> + Default> Default
    for Parameters<G, P>
{
    fn default() -> Self {
        Self {
            threshold: 0,
            limit: 0,
            message_generator: G::identity(),
            blinder_generator: G::identity(),
            participant_number_generator: P::default(),
        }
    }
}

impl<
        G: GroupHasher + GroupEncoding + Default,
        P: ParticipantNumberGenerator<G::Scalar> + Default,
    > Parameters<G, P>
{
    /// Create regular parameters with the message_generator as the default generator
    /// and a random blinder_generator
    pub fn new(
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
        message_generator: Option<G>,
        blinder_generator: Option<G>,
        participant_number_generator: Option<P>,
    ) -> Self {
        let message_generator = message_generator.unwrap_or_else(G::generator);
        let blinder_generator = blinder_generator
            .unwrap_or_else(|| G::hash_to_curve(message_generator.to_bytes().as_ref()));
        let participant_number_generator = participant_number_generator.unwrap_or_default();
        Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator,
            blinder_generator,
            participant_number_generator,
        }
    }

    /// The threshold parameter
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The limit parameter
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Get the message generator
    pub fn message_generator(&self) -> G {
        self.message_generator
    }

    /// Get the blinder generator
    pub fn blinder_generator(&self) -> G {
        self.blinder_generator
    }

    /// Get the participant number generator
    pub fn participant_number_generator(&self) -> &P {
        &self.participant_number_generator
    }
}
