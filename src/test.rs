#![cfg(test)]

use super::*;
use ed25519_dalek::Keypair;
use rand::thread_rng;
use soroban_sdk::testutils::ed25519::Sign;

use soroban_auth::{Ed25519Signature, SignaturePayload, SignaturePayloadV0};
use soroban_sdk::{vec, BytesN, Env, RawVal, Symbol, Vec};

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn make_identifier(e: &Env, kp: &Keypair) -> Identifier {
    Identifier::Ed25519(kp.public.to_bytes().into_val(e))
}

fn make_signature(e: &Env, kp: &Keypair, function: &str, args: Vec<RawVal>) -> Signature {
    let msg = SignaturePayload::V0(SignaturePayloadV0 {
        function: Symbol::from_str(function),
        contract: BytesN::from_array(e, &[0; 32]),
        network: e.ledger().network_passphrase(),
        args,
    });
    Signature::Ed25519(Ed25519Signature {
        public_key: BytesN::from_array(e, &kp.public.to_bytes()),
        signature: kp.sign(msg).unwrap().into_val(e),
    })
}

#[test]
fn test_add_identity() {
    let env = Env::default();
    let contract_id = BytesN::from_array(&env, &[0; 32]);
    env.register_contract(&contract_id, IdentityContract);
    let client = IdentityContractClient::new(&env, contract_id);

    let user_kp = generate_keypair();
    let user_id = make_identifier(&env, &user_kp);
    let user_nonce = client.nonce(&user_id);

    let sig = make_signature(
        &env,
        &user_kp,
        "write_iden",
        (
            &user_id,
            user_nonce.clone(),
            BytesN::from_array(&env, &[0; 32]),
        )
            .into_val(&env),
    );

    client.write_iden(
        &BytesN::from_array(&env, &[0; 32]),
        &Bytes::from_array(&env, &[116, 100, 101, 112]), // "tdep"
        &Bytes::from_array(
            &env,
            &[
                65, 32, 100, 101, 118, 101, 108, 111, 112, 101, 114, 32, 116, 104, 97, 116, 32, 98,
                117, 105, 108, 100, 32, 115, 116, 117, 102, 102,
            ],
        ), // "A developer that build stuff"
        &vec![
            &env,
            Link {
                descr: Bytes::from_array(
                    &env,
                    &[112, 101, 114, 115, 111, 110, 97, 108, 32, 98, 108, 111, 103],
                ), // "personal blog"
                link: Bytes::from_array(
                    &env,
                    &[
                        104, 116, 116, 112, 115, 58, 47, 47, 104, 101, 121, 116, 100, 101, 112, 46,
                        103, 105, 116, 104, 117, 98, 46, 105, 111, 47,
                    ],
                ), // "https://heytdep.github.io/"
            },
        ],
        &sig,
        &user_nonce,
    );

    let iden = client.get_iden(&BytesN::from_array(&env, &[0; 32]));
    assert_eq!(iden.name, Bytes::from_array(&env, &[116, 100, 101, 112]));
}
