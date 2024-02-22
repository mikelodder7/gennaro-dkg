use gennaro_dkg::*;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use vsss_rs::{
    combine_shares,
    curve25519::*,
    elliptic_curve::{group::GroupEncoding, Group},
    Share,
};

#[cfg(test)]
mod init_dkg {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_init::<k256::ProjectivePoint>();
    }

    #[test]
    fn five_participants_p256() {
        five_participants_init::<p256::ProjectivePoint>();
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_init::<WrappedRistretto>();
        five_participants_init::<WrappedEdwards>();
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_init::<bls12_381_plus::G1Projective>();
        five_participants_init::<bls12_381_plus::G2Projective>();
    }
}

// Previous threshold was 3
#[cfg(test)]
mod add_participant_same_threshold {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_add_participant::<k256::ProjectivePoint>(3);
    }

    #[test]
    fn five_participants_p256() {
        five_participants_add_participant::<p256::ProjectivePoint>(3);
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_add_participant::<WrappedRistretto>(3);
        five_participants_add_participant::<WrappedEdwards>(3);
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_add_participant::<bls12_381_plus::G1Projective>(3);
        five_participants_add_participant::<bls12_381_plus::G2Projective>(3);
    }
}

// Previous threshold was 3, new threshold is 5
#[cfg(test)]
mod add_participant_increase_threshold {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_add_participant::<k256::ProjectivePoint>(5);
    }

    #[test]
    fn five_participants_p256() {
        five_participants_add_participant::<p256::ProjectivePoint>(5);
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_add_participant::<WrappedRistretto>(4);
        five_participants_add_participant::<WrappedEdwards>(5);
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_add_participant::<bls12_381_plus::G1Projective>(5);
        five_participants_add_participant::<bls12_381_plus::G2Projective>(4);
    }
}

// Previous threshold was 3
#[cfg(test)]
mod remove_participant_same_threshold {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_remove_participant::<k256::ProjectivePoint>(3);
    }

    #[test]
    fn five_participants_p256() {
        five_participants_remove_participant::<p256::ProjectivePoint>(3);
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_remove_participant::<WrappedRistretto>(3);
        five_participants_remove_participant::<WrappedEdwards>(3);
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_remove_participant::<bls12_381_plus::G1Projective>(3);
        five_participants_remove_participant::<bls12_381_plus::G2Projective>(3);
    }
}

// Previous threshold was 3, new threshold is 2
#[cfg(test)]
mod remove_participant_decrease_threshold {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_remove_participant::<k256::ProjectivePoint>(2);
    }

    #[test]
    fn five_participants_p256() {
        five_participants_remove_participant::<p256::ProjectivePoint>(2);
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_remove_participant::<WrappedRistretto>(2);
        five_participants_remove_participant::<WrappedEdwards>(2);
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_remove_participant::<bls12_381_plus::G1Projective>(2);
        five_participants_remove_participant::<bls12_381_plus::G2Projective>(2);
    }
}

#[cfg(test)]
mod add_and_remove_participant_increase_participant {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_add_and_remove_increase_participant::<k256::ProjectivePoint>(5);
    }

    #[test]
    fn five_participants_p256() {
        five_participants_add_and_remove_increase_participant::<p256::ProjectivePoint>(4);
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_add_and_remove_increase_participant::<WrappedRistretto>(6);
        five_participants_add_and_remove_increase_participant::<WrappedEdwards>(2);
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_add_and_remove_increase_participant::<bls12_381_plus::G1Projective>(5);
        five_participants_add_and_remove_increase_participant::<bls12_381_plus::G2Projective>(2);
    }
}

#[cfg(test)]
mod add_and_remove_participant_decrease_participant {
    use super::*;

    #[test]
    fn five_participants_k256() {
        five_participants_add_and_remove_decrease_participant::<k256::ProjectivePoint>(3);
    }

    #[test]
    fn five_participants_p256() {
        five_participants_add_and_remove_decrease_participant::<p256::ProjectivePoint>(4);
    }

    #[test]
    fn five_participants_curve25519() {
        five_participants_add_and_remove_decrease_participant::<WrappedRistretto>(3);
        five_participants_add_and_remove_decrease_participant::<WrappedEdwards>(2);
    }

    #[test]
    fn five_participants_bls12381() {
        five_participants_add_and_remove_decrease_participant::<bls12_381_plus::G1Projective>(3);
        five_participants_add_and_remove_decrease_participant::<bls12_381_plus::G2Projective>(4);
    }
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
    for p in participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
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

    let res = combine_shares::<G::Scalar, [u8; 4], u32, InnerShare>(&r4shares);
    assert!(res.is_ok());
    let secret = res.unwrap();

    // println!("Old Public - {:?}", (G::generator() * secret).to_bytes().as_ref());

    assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&2].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&3].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&4].public_key, G::generator() * secret);
    assert_eq!(r4bdata[&5].public_key, G::generator() * secret);

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
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
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

    let res = combine_shares::<G::Scalar, [u8; 4], u32, InnerShare>(&r4shares);
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
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }

    for p in &participants {
        assert!(p.round5(&r4bdata).is_ok());
    }

    assert!(participants[0].get_public_key().unwrap() == participants[1].get_public_key().unwrap());

    let res = combine_shares::<G::Scalar, [u8; 4], u32, InnerShare>(&r4shares);
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
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
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

    let res = combine_shares::<G::Scalar, [u8; 4], u32, InnerShare>(&r4shares);
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
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
        assert!(p.round4(&r3bdata).is_err());
    }
    for p in new_participants.iter_mut() {
        let res = p.round4(&r3bdata);
        assert!(res.is_ok());
        let bdata = res.unwrap();
        let share = p.get_secret_share().unwrap();
        r4bdata.insert(p.get_id(), bdata);
        r4shares.push(<InnerShare as Share>::from_field_element(p.get_id() as u32, share).unwrap());
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

    let res = combine_shares::<G::Scalar, [u8; 4], u32, InnerShare>(&r4shares);
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
