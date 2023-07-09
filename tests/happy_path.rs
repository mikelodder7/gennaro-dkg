use gennaro_dkg::*;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use vsss_rs::{
    combine_shares,
    curve25519::*,
    elliptic_curve::{group::GroupEncoding, Group},
    Share,
};

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
        SecretParticipant::<G>::new(NonZeroUsize::new(1).unwrap(), parameters).unwrap(),
        SecretParticipant::<G>::new(NonZeroUsize::new(2).unwrap(), parameters).unwrap(),
        SecretParticipant::<G>::new(NonZeroUsize::new(3).unwrap(), parameters).unwrap(),
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
    let res_p0 = serde_json::from_str::<SecretParticipant<G>>(&participant_json);
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
        r4shares.push(<Vec<u8> as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());
    assert!(participants[1].get_public_key().unwrap() == participants[2].get_public_key().unwrap());

    let res = combine_shares::<G::Scalar, u8, Vec<u8>>(&r4shares);
    assert!(res.is_ok());
    let secret = res.unwrap();

    // println!("Old Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * secret);

    // Next epoch
    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT + 1).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);

    let share_ids = [
        G::Scalar::from(1),
        G::Scalar::from(2),
        G::Scalar::from(3),
    ];

    let mut participants = [
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(1).unwrap(),
            parameters,
            participants[0].get_secret_share().unwrap(), 
            &share_ids,
            0)
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(2).unwrap(),
            parameters,
            participants[1].get_secret_share().unwrap(), 
            &share_ids,
            1)
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(3).unwrap(),
            parameters,
            participants[2].get_secret_share().unwrap(), 
            &share_ids,
            2)
        .unwrap(),
    ];
    let mut new_participant = RefreshParticipant::<G>::new(NonZeroUsize::new(4).unwrap(), parameters).unwrap();

    // Round 1
    let mut r1bdata = Vec::with_capacity(LIMIT + 1);
    let mut r1p2pdata = Vec::with_capacity(LIMIT + 1);
    for p in participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }
    let (broadcast, p2p) = new_participant.round1().expect("Round 1 should work");
    r1bdata.push(broadcast);
    r1p2pdata.push(p2p);

    for p in participants.iter_mut() {
        assert!(p.round1().is_err());
    }
    assert!(new_participant.round1().is_err());

    // Round 2
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
        let id = new_participant.get_id();
        bdata.insert(id, r1bdata[id - 1].clone());
        p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());

        let p = &mut participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }

    let mut bdata = BTreeMap::new();
    let mut p2pdata = BTreeMap::new();

    let my_id = new_participant.get_id();
    for j in 0..LIMIT {
        let pp = &participants[j];
        let id = pp.get_id();
        bdata.insert(id, r1bdata[id - 1].clone());
        p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
    }

    let res = new_participant.round2(bdata, p2pdata);
    assert!(res.is_ok());
    r2bdata.insert(my_id, res.unwrap());

    // Round 3
    let mut r3bdata = BTreeMap::new();
    for p in participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }

    let res = new_participant.round3(&r2bdata);
    assert!(res.is_ok());
    r3bdata.insert(new_participant.get_id(), res.unwrap());
    assert!(new_participant.round3(&r2bdata).is_err());

    // Round 4
    let mut r4bdata = BTreeMap::new();
    let mut r4shares = Vec::with_capacity(LIMIT + 1);
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<Vec<u8> as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    let res = new_participant.round4(&r3bdata);
    assert!(res.is_ok());
    let bdata = res.unwrap();
    let share = new_participant.get_secret_share().unwrap();
    r4bdata.insert(new_participant.get_id(), bdata);
    r4shares.push(<Vec<u8> as Share>::from_field_element(new_participant.get_id() as u8, share).unwrap());
    assert!(new_participant.round4(&r3bdata).is_err());

    // Round 5
    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(new_participant.round5(&r4bdata).is_ok());

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());
    assert!(participants[1].get_public_key().unwrap() == participants[2].get_public_key().unwrap());
    assert!(participants[2].get_public_key().unwrap() == new_participant.get_public_key().unwrap());
    assert!(participants[0].get_public_key().unwrap() == new_participant.get_public_key().unwrap());

    let res = combine_shares::<G::Scalar, u8, Vec<u8>>(&r4shares);
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    // println!("New Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&4].public_key, G::generator() * secret);

    // Old shared secret remains unchanged
    assert_eq!(secret, new_secret);
}
