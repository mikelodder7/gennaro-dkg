use elliptic_curve::group::GroupEncoding;
use elliptic_curve::{Group, PrimeField};
use gennaro_dkg::*;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use vsss_rs::{curve25519::*, Shamir, Share};

#[test]
fn three_participants_k256() {
    three_participants::<k256::ProjectivePoint>()
}

#[test]
fn three_participants_p256() {
    three_participants::<p256::ProjectivePoint>()
}

#[test]
fn three_participants_curve25519() {
    three_participants::<WrappedRistretto>();
    three_participants::<WrappedEdwards>();
}

#[test]
fn three_participants_bls12381() {
    three_participants::<bls12_381_plus::G1Projective>();
    three_participants::<bls12_381_plus::G2Projective>();
}

fn three_participants<G: Group + GroupEncoding + Default>() {
    const THRESHOLD: usize = 2;
    const LIMIT: usize = 3;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);
    let mut participants = [
        SecretParticipant::<G, DefaultLogger>::new(NonZeroUsize::new(1).unwrap(), parameters)
            .unwrap(),
        SecretParticipant::<G, DefaultLogger>::new(NonZeroUsize::new(2).unwrap(), parameters)
            .unwrap(),
        SecretParticipant::<G, DefaultLogger>::new(NonZeroUsize::new(3).unwrap(), parameters)
            .unwrap(),
    ];

    let mut r1bdata = Vec::with_capacity(LIMIT);
    let mut r1p2pdata = Vec::with_capacity(LIMIT);
    for p in participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }
    for p in participants.iter_mut() {
        assert!(p.round1().is_err());
    }

    // serialize test

    let res_participant_json = serde_json::to_string(&participants[0]);
    assert!(res_participant_json.is_ok());
    let participant_json = res_participant_json.unwrap();
    let res_p0 = serde_json::from_str::<SecretParticipant<G, DefaultLogger>>(&participant_json);
    assert!(res_p0.is_ok());
    let p0 = res_p0.unwrap();
    assert_eq!(p0.get_id(), participants[0].get_id());

    let mut r2bdata = BTreeMap::new();

    for i in 0..LIMIT {
        let mut bdata = BTreeMap::new();
        let mut p2pdata = BTreeMap::new();

        let my_id = participants[i].get_id();
        for j in 0..LIMIT {
            let pp = &participants[j];
            let id = pp.get_id();
            if my_id == id {
                continue;
            }
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }
        let p = &mut participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }

    let mut r3bdata = BTreeMap::new();
    for p in participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }

    let mut r4bdata = BTreeMap::new();
    let mut r4shares = Vec::with_capacity(LIMIT);
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        let mut pshare = share.to_repr().as_ref().to_vec();
        pshare.insert(0, p.get_id() as u8);
        r4shares.push(Share(pshare));
        assert!(p.round4(&r3bdata).is_err());
    }

    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    let res = Shamir {
        t: THRESHOLD,
        n: LIMIT,
    }
    .combine_shares::<G::Scalar>(&r4shares);
    assert!(res.is_ok());
    let secret = res.unwrap();

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
}
