use gennaro_dkg::*;
use rstest::*;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use vsss_rs::{
    combine_shares,
    curve25519::*,
    elliptic_curve::{group::GroupEncoding, Group},
    Share,
};

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY)]
#[case::p256(p256::ProjectivePoint::IDENTITY)]
#[case::ed25519(WrappedEdwards::default())]
#[case::ristretto25519(WrappedRistretto::default())]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY)]
fn init_dkg<G: Group + GroupEncoding + Default>(#[case] _g: G) {
    five_participants_init::<G>();
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 3)]
#[case::ed25519(WrappedEdwards::default(), 3)]
#[case::ristretto25519(WrappedRistretto::default(), 3)]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY, 3)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY, 3)]
fn add_participant_same_threshold<G: Group + GroupEncoding + Default>(
    #[case] _g: G,
    #[case] threshold: usize,
) {
    five_participants_add_participant::<G>(threshold);
}

// Previous threshold was 3, new threshold is 5
#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 5)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 5)]
#[case::ed25519(WrappedEdwards::default(), 5)]
#[case::ristretto25519(WrappedRistretto::default(), 5)]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY, 5)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY, 4)]
fn add_participant_increase_threshold<G: Group + GroupEncoding + Default>(
    #[case] _g: G,
    #[case] threshold: usize,
) {
    five_participants_add_participant::<G>(threshold);
}

// Previous threshold was 3
#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 3)]
#[case::ed25519(WrappedEdwards::default(), 3)]
#[case::ristretto25519(WrappedRistretto::default(), 3)]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY, 3)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY, 3)]
fn remove_participant_same_threshold<G: Group + GroupEncoding + Default>(
    #[case] _g: G,
    #[case] threshold: usize,
) {
    five_participants_remove_participant::<G>(threshold);
}

// Previous threshold was 3, new threshold is 2
#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 2)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 2)]
#[case::ed25519(WrappedEdwards::default(), 2)]
#[case::ristretto25519(WrappedRistretto::default(), 2)]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY, 2)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY, 2)]
fn remove_participant_decrease_threshold<G: Group + GroupEncoding + Default>(
    #[case] _g: G,
    #[case] threshold: usize,
) {
    five_participants_remove_participant::<G>(threshold);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 5)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 5)]
#[case::ed25519(WrappedEdwards::default(), 5)]
#[case::ristretto25519(WrappedRistretto::default(), 5)]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY, 5)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY, 2)]
fn add_and_remove_participant_increase_participant<G: Group + GroupEncoding + Default>(
    #[case] _g: G,
    #[case] threshold: usize,
) {
    five_participants_add_and_remove_increase_participant::<G>(threshold);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 4)]
#[case::ed25519(WrappedEdwards::default(), 3)]
#[case::ristretto25519(WrappedRistretto::default(), 2)]
#[case::bls12_381_g1(blsful::inner_types::G1Projective::IDENTITY, 3)]
#[case::bls12_381_g2(blsful::inner_types::G2Projective::IDENTITY, 4)]
fn add_and_remove_participant_decrease_participant<G: Group + GroupEncoding + Default>(
    #[case] _g: G,
    #[case] threshold: usize,
) {
    five_participants_add_and_remove_decrease_participant::<G>(threshold);
}

fn five_participants_init<G: Group + GroupEncoding + Default>(
) -> (Vec<SecretParticipant<G>>, <G as Group>::Scalar) {
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);
    let mut participants = vec![
        SecretParticipant::<G>::new(NonZeroUsize::new(1).unwrap(), parameters).unwrap(),
        SecretParticipant::<G>::new(NonZeroUsize::new(2).unwrap(), parameters).unwrap(),
        SecretParticipant::<G>::new(NonZeroUsize::new(3).unwrap(), parameters).unwrap(),
        SecretParticipant::<G>::new(NonZeroUsize::new(4).unwrap(), parameters).unwrap(),
        SecretParticipant::<G>::new(NonZeroUsize::new(5).unwrap(), parameters).unwrap(),
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
    let mut r4blind_shares = Vec::with_capacity(LIMIT);
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        let blind_share = p.get_blind_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        r4blind_shares.push(
            <InnerShare as Share>::from_field_element(p.get_id() as u8, blind_share).unwrap(),
        );
        assert!(p.round4(&r3bdata).is_err());
    }

    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());
    assert!(participants[1].get_public_key().unwrap() == participants[2].get_public_key().unwrap());
    assert!(participants[2].get_public_key().unwrap() == participants[3].get_public_key().unwrap());
    assert!(participants[3].get_public_key().unwrap() == participants[4].get_public_key().unwrap());
    assert!(participants[4].get_public_key().unwrap() == participants[1].get_public_key().unwrap());

    let res = combine_shares::<G::Scalar, [u8; 1], u8, InnerShare>(&r4shares);
    assert!(res.is_ok());
    let secret = res.unwrap();

    // println!("Old Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&4].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&5].public_key, G::generator() * secret);

    let res = combine_shares::<G::Scalar, [u8; 1], u8, InnerShare>(&r4blind_shares);
    assert!(res.is_ok());

    (participants, secret)
}

fn five_participants_add_participant<G: Group + GroupEncoding + Default>(threshold: usize) {
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    let THRESHOLD: usize = threshold;
    const LIMIT: usize = 5;
    const INCREMENT: usize = 2;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);

    let share_ids = [
        G::Scalar::from(1),
        G::Scalar::from(2),
        G::Scalar::from(3),
        G::Scalar::from(4),
        G::Scalar::from(5),
    ];

    let mut participants = [
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(1).unwrap(),
            parameters,
            participants[0].get_secret_share().unwrap(),
            &share_ids,
            0,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(2).unwrap(),
            parameters,
            participants[1].get_secret_share().unwrap(),
            &share_ids,
            1,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(3).unwrap(),
            parameters,
            participants[2].get_secret_share().unwrap(),
            &share_ids,
            2,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(4).unwrap(),
            parameters,
            participants[3].get_secret_share().unwrap(),
            &share_ids,
            3,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(5).unwrap(),
            parameters,
            participants[4].get_secret_share().unwrap(),
            &share_ids,
            4,
        )
        .unwrap(),
    ];
    let mut new_participants = [
        RefreshParticipant::<G>::new(NonZeroUsize::new(6).unwrap(), parameters).unwrap(),
        RefreshParticipant::<G>::new(NonZeroUsize::new(7).unwrap(), parameters).unwrap(),
    ];

    // Round 1
    let mut r1bdata = Vec::with_capacity(LIMIT + INCREMENT);
    let mut r1p2pdata = Vec::with_capacity(LIMIT + INCREMENT);
    for p in participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }
    for p in new_participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }

    for p in participants.iter_mut() {
        assert!(p.round1().is_err());
    }
    for p in new_participants.iter_mut() {
        assert!(p.round1().is_err());
    }

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
        for j in 0..INCREMENT {
            let pp = &new_participants[j];
            let id = pp.get_id();
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }

        let p = &mut participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }
    for i in 0..INCREMENT {
        let mut bdata = BTreeMap::new();
        let mut p2pdata = BTreeMap::new();

        let my_id = new_participants[i].get_id();
        for j in 0..LIMIT {
            let pp = &participants[j];
            let id = pp.get_id();
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }
        for j in 0..INCREMENT {
            let pp = &new_participants[j];
            let id = pp.get_id();
            if my_id == id {
                continue;
            }
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }

        let p = &mut new_participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }

    // Round 3
    let mut r3bdata = BTreeMap::new();
    for p in participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }

    // Round 4
    let mut r4bdata = BTreeMap::new();
    let mut r4shares = Vec::with_capacity(LIMIT + INCREMENT);
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    // Round 5
    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }
    for p in &new_participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());
    assert!(participants[1].get_public_key().unwrap() == participants[2].get_public_key().unwrap());
    assert!(participants[2].get_public_key().unwrap() == participants[3].get_public_key().unwrap());
    assert!(participants[3].get_public_key().unwrap() == participants[4].get_public_key().unwrap());
    assert!(
        participants[4].get_public_key().unwrap() == new_participants[0].get_public_key().unwrap()
    );
    assert!(
        new_participants[0].get_public_key().unwrap()
            == new_participants[1].get_public_key().unwrap()
    );
    assert!(
        new_participants[1].get_public_key().unwrap() == participants[0].get_public_key().unwrap()
    );

    let res = combine_shares::<G::Scalar, [u8; 1], u8, InnerShare>(&r4shares);
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    // println!("New Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&4].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&5].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&6].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&7].public_key, G::generator() * secret);

    // Old shared secret remains unchanged
    assert_eq!(secret, new_secret);
}

fn five_participants_remove_participant<G: Group + GroupEncoding + Default>(threshold: usize) {
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    let THRESHOLD: usize = threshold;
    const LIMIT: usize = 3;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);

    let share_ids = [G::Scalar::from(1), G::Scalar::from(3), G::Scalar::from(4)];

    let mut participants = [
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(1).unwrap(),
            parameters,
            participants[0].get_secret_share().unwrap(),
            &share_ids,
            0,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(2).unwrap(),
            parameters,
            participants[2].get_secret_share().unwrap(),
            &share_ids,
            1,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(3).unwrap(),
            parameters,
            participants[3].get_secret_share().unwrap(),
            &share_ids,
            2,
        )
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
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());

    let res = combine_shares::<G::Scalar, [u8; 1], u8, InnerShare>(&r4shares);
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    // println!("Old Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * new_secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * new_secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * new_secret);

    // Old shared secret remains unchanged
    assert_eq!(secret, new_secret);
}

fn five_participants_add_and_remove_decrease_participant<G: Group + GroupEncoding + Default>(
    threshold: usize,
) {
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    let THRESHOLD: usize = threshold;
    const LIMIT: usize = 3;
    const INCREMENT: usize = 1;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);

    let share_ids = [G::Scalar::from(2), G::Scalar::from(3), G::Scalar::from(4)];

    let mut participants = [
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(1).unwrap(),
            parameters,
            participants[1].get_secret_share().unwrap(),
            &share_ids,
            0,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(2).unwrap(),
            parameters,
            participants[2].get_secret_share().unwrap(),
            &share_ids,
            1,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(3).unwrap(),
            parameters,
            participants[3].get_secret_share().unwrap(),
            &share_ids,
            2,
        )
        .unwrap(),
    ];

    let mut new_participants =
        [RefreshParticipant::<G>::new(NonZeroUsize::new(4).unwrap(), parameters).unwrap()];

    // Round 1
    let mut r1bdata = Vec::with_capacity(LIMIT + INCREMENT);
    let mut r1p2pdata = Vec::with_capacity(LIMIT + INCREMENT);
    for p in participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }
    for p in new_participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }

    for p in participants.iter_mut() {
        assert!(p.round1().is_err());
    }
    for p in new_participants.iter_mut() {
        assert!(p.round1().is_err());
    }

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
        for j in 0..INCREMENT {
            let pp = &new_participants[j];
            let id = pp.get_id();
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }

        let p = &mut participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }
    for i in 0..INCREMENT {
        let mut bdata = BTreeMap::new();
        let mut p2pdata = BTreeMap::new();

        let my_id = new_participants[i].get_id();
        for j in 0..LIMIT {
            let pp = &participants[j];
            let id = pp.get_id();
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }
        for j in 0..INCREMENT {
            let pp = &new_participants[j];
            let id = pp.get_id();
            if my_id == id {
                continue;
            }
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }

        let p = &mut new_participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }

    // Round 3
    let mut r3bdata = BTreeMap::new();
    for p in participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }

    // Round 4
    let mut r4bdata = BTreeMap::new();
    let mut r4shares = Vec::with_capacity(LIMIT + INCREMENT);
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    // Round 5
    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }
    for p in &new_participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());
    assert!(participants[1].get_public_key().unwrap() == participants[2].get_public_key().unwrap());
    assert!(
        participants[2].get_public_key().unwrap() == new_participants[0].get_public_key().unwrap()
    );
    assert!(
        new_participants[0].get_public_key().unwrap() == participants[0].get_public_key().unwrap()
    );

    let res = combine_shares::<G::Scalar, [u8; 1], u8, InnerShare>(&r4shares);
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

fn five_participants_add_and_remove_increase_participant<G: Group + GroupEncoding + Default>(
    threshold: usize,
) {
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    let THRESHOLD: usize = threshold;
    const LIMIT: usize = 3;
    const INCREMENT: usize = 3;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit);

    let share_ids = [G::Scalar::from(2), G::Scalar::from(3), G::Scalar::from(5)];

    let mut participants = [
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(1).unwrap(),
            parameters,
            participants[1].get_secret_share().unwrap(),
            &share_ids,
            0,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(2).unwrap(),
            parameters,
            participants[2].get_secret_share().unwrap(),
            &share_ids,
            1,
        )
        .unwrap(),
        SecretParticipant::<G>::with_secret(
            NonZeroUsize::new(3).unwrap(),
            parameters,
            participants[4].get_secret_share().unwrap(),
            &share_ids,
            2,
        )
        .unwrap(),
    ];

    let mut new_participants = [
        RefreshParticipant::<G>::new(NonZeroUsize::new(4).unwrap(), parameters).unwrap(),
        RefreshParticipant::<G>::new(NonZeroUsize::new(5).unwrap(), parameters).unwrap(),
        RefreshParticipant::<G>::new(NonZeroUsize::new(6).unwrap(), parameters).unwrap(),
    ];

    // Round 1
    let mut r1bdata = Vec::with_capacity(LIMIT + INCREMENT);
    let mut r1p2pdata = Vec::with_capacity(LIMIT + INCREMENT);
    for p in participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }
    for p in new_participants.iter_mut() {
        let (broadcast, p2p) = p.round1().expect("Round 1 should work");
        r1bdata.push(broadcast);
        r1p2pdata.push(p2p);
    }

    for p in participants.iter_mut() {
        assert!(p.round1().is_err());
    }
    for p in new_participants.iter_mut() {
        assert!(p.round1().is_err());
    }

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
        for j in 0..INCREMENT {
            let pp = &new_participants[j];
            let id = pp.get_id();
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }

        let p = &mut participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }
    for i in 0..INCREMENT {
        let mut bdata = BTreeMap::new();
        let mut p2pdata = BTreeMap::new();

        let my_id = new_participants[i].get_id();
        for j in 0..LIMIT {
            let pp = &participants[j];
            let id = pp.get_id();
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }
        for j in 0..INCREMENT {
            let pp = &new_participants[j];
            let id = pp.get_id();
            if my_id == id {
                continue;
            }
            bdata.insert(id, r1bdata[id - 1].clone());
            p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
        }

        let p = &mut new_participants[i];
        let res = p.round2(bdata, p2pdata);
        assert!(res.is_ok());
        r2bdata.insert(my_id, res.unwrap());
    }

    // Round 3
    let mut r3bdata = BTreeMap::new();
    for p in participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round3(&r2bdata);
        assert!(res.is_ok());
        r3bdata.insert(p.get_id(), res.unwrap());
        assert!(p.round3(&r2bdata).is_err());
    }

    // Round 4
    let mut r4bdata = BTreeMap::new();
    let mut r4shares = Vec::with_capacity(LIMIT + INCREMENT);
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    // Round 5
    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }
    for p in &new_participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());
    assert!(participants[1].get_public_key().unwrap() == participants[2].get_public_key().unwrap());
    assert!(
        participants[2].get_public_key().unwrap() == new_participants[0].get_public_key().unwrap()
    );
    assert!(
        new_participants[0].get_public_key().unwrap()
            == new_participants[1].get_public_key().unwrap()
    );
    assert!(
        new_participants[1].get_public_key().unwrap()
            == new_participants[2].get_public_key().unwrap()
    );
    assert!(
        new_participants[2].get_public_key().unwrap() == participants[0].get_public_key().unwrap()
    );

    let res = combine_shares::<G::Scalar, [u8; 1], u8, InnerShare>(&r4shares);
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    // println!("New Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&4].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&5].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&6].public_key, G::generator() * secret);

    // Old shared secret remains unchanged
    assert_eq!(secret, new_secret);
}
