use blsful::inner_types::GroupEncoding;
use elliptic_curve::Group;
use elliptic_curve_tools::SumOfProducts;
use gennaro_dkg::{
    AnyParticipant, GroupHasher, Parameters, ParticipantRoundOutput, RefreshParticipant, Round,
    RoundOutputGenerator, SecretParticipant,
};
use std::num::NonZero;
use vsss_rs::{IdentifierPrimeField, ReadableShareSet};

#[test]
fn dkg_and_refresh() {
    const REKEYS: usize = 5;
    const REFRESHES: usize = 5;
    const THRESHOLD: usize = 3;
    const PARTIES: usize = 5;

    let params = Parameters::new(
        NonZero::new(THRESHOLD).unwrap(),
        NonZero::new(PARTIES).unwrap(),
        None,
        None,
        None,
    );

    for i in 0..REKEYS {
        let mut participants =
            Vec::<Box<dyn AnyParticipant<jubjub_plus::SubgroupPoint> + 'static>>::with_capacity(
                PARTIES,
            );
        for j in 1..=PARTIES {
            let p = SecretParticipant::<jubjub_plus::SubgroupPoint>::new(
                IdentifierPrimeField(jubjub_plus::Scalar::from(j as u64)),
                &params,
            )
            .unwrap();
            participants.push(Box::new(p));
        }

        for _ in [
            Round::One,
            Round::Two,
            Round::Three,
            Round::Four,
            Round::Five,
        ] {
            let round_generators = run_next_round::<jubjub_plus::SubgroupPoint>(&mut participants);
            receive_round_output(&mut participants, &round_generators);
        }

        let mut shares = participants
            .iter()
            .map(|p| p.get_secret_share().unwrap())
            .collect::<Vec<gennaro_dkg::SecretShare<jubjub_plus::Scalar>>>();
        let secret = (&shares[..THRESHOLD]).combine().unwrap();
        assert_eq!(
            jubjub_plus::SubgroupPoint::generator() * secret.0,
            participants[0].get_public_key().unwrap(),
            "Secret key does not match the public key, rekey {}",
            i
        );

        for j in 0..REFRESHES {
            let mut refresh_parties = Vec::<
                Box<dyn AnyParticipant<jubjub_plus::SubgroupPoint> + 'static>,
            >::with_capacity(PARTIES);
            for k in 1..=PARTIES {
                let p = RefreshParticipant::<jubjub_plus::SubgroupPoint>::new(
                    IdentifierPrimeField(jubjub_plus::Scalar::from(k as u64)),
                    &params,
                )
                .unwrap();
                refresh_parties.push(Box::new(p));
            }

            for _ in [
                Round::One,
                Round::Two,
                Round::Three,
                Round::Four,
                Round::Five,
            ] {
                let round_generators =
                    run_next_round::<jubjub_plus::SubgroupPoint>(&mut refresh_parties);
                receive_round_output(&mut refresh_parties, &round_generators);
            }
            let refresh_shares = refresh_parties
                .iter()
                .map(|p| p.get_secret_share().unwrap())
                .collect::<Vec<gennaro_dkg::SecretShare<jubjub_plus::Scalar>>>();
            let refresh_secret = (&refresh_shares[..]).combine().unwrap();
            assert_eq!(
                refresh_secret.0,
                jubjub_plus::Scalar::zero(),
                "Refresh secret is not zero, rekey {}, refresh {}",
                i,
                j
            );

            let mut cloned_shares = shares.clone();
            for (share, refresh_share) in cloned_shares.iter_mut().zip(refresh_shares.iter()) {
                assert_eq!(
                    share.identifier.0, refresh_share.identifier.0,
                    "Share identifiers do not match, rekey {}, refresh {}",
                    i, j
                );
                share.value.0 += refresh_share.value.0;
            }

            let refreshed_secret = (&cloned_shares[..THRESHOLD]).combine().unwrap();
            assert_eq!(
                refreshed_secret.0, secret.0,
                "Refreshed secret does not match the original secret, rekey {}, refresh {}",
                i, j
            );
            shares = cloned_shares;
        }
    }
}

fn run_next_round<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
    participants: &mut [Box<dyn AnyParticipant<G>>],
) -> Vec<RoundOutputGenerator<G>> {
    let mut round_generators = Vec::with_capacity(participants.len());
    for participant in participants {
        let generator = participant.run().unwrap();
        round_generators.push(generator);
    }
    round_generators
}

fn receive_round_output<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
    participants: &mut [Box<dyn AnyParticipant<G>>],
    round_generators: &[RoundOutputGenerator<G>],
) {
    for round_generator in round_generators {
        for ParticipantRoundOutput {
            dst_ordinal: ordinal,
            dst_id: id,
            data,
            ..
        } in round_generator.iter()
        {
            if let Some(participant) = participants.get_mut(ordinal) {
                assert_eq!(participant.get_ordinal(), ordinal);
                assert_eq!(participant.get_id(), id);
                let res = participant.receive(data.as_slice());
                assert!(res.is_ok());
            }
        }
    }
}
