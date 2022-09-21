#![no_std]

#[cfg(feature = "testutils")]
extern crate std;

mod test;

use soroban_auth::{
    check_auth, NonceAuth, {Identifier, Signature},
};
use soroban_sdk::{contractimpl, contracttype, symbol, BigInt, Bytes, BytesN, Env, IntoVal, Vec};

#[contracttype]
pub enum DataKey {
    Registered(BytesN<32>),
    Nonce(Identifier),
    Admin,
}

#[contracttype]
pub struct Link {
    pub descr: Bytes,
    pub link: Bytes,
}

#[contracttype]
pub struct Identity {
    pub name: Bytes,
    pub descr: Bytes,
    pub links: Vec<Link>,
    pub admin: Identifier,
}

impl Identity {
    fn new(name: Bytes, descr: Bytes, links: Vec<Link>, admin: Identifier) -> Self {
        Identity {
            name,
            descr,
            links,
            admin,
        }
    }
}

// Signature stuff

fn read_nonce(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Nonce(id);
    e.contract_data()
        .get(key)
        .unwrap_or_else(|| Ok(BigInt::zero(e)))
        .unwrap()
}

struct NonceForSignature(Signature);

impl NonceAuth for NonceForSignature {
    fn read_nonce(e: &Env, id: Identifier) -> BigInt {
        read_nonce(e, id)
    }

    fn read_and_increment_nonce(&self, e: &Env, id: Identifier) -> BigInt {
        let key = DataKey::Nonce(id.clone());
        let nonce = Self::read_nonce(e, id);
        e.contract_data().set(key, &nonce + 1);

        nonce
    }

    fn signature(&self) -> &Signature {
        &self.0
    }
}

pub struct IdentityContract;

#[contractimpl]
impl IdentityContract {
    pub fn set_admin(e: Env, admin: Identifier) {
        if e.contract_data().has(DataKey::Admin) {
            panic!("can't write a new admin")
        }
        let key = DataKey::Admin;
        e.contract_data().set(key, admin);
    }

    pub fn get_admin(e: Env) -> Identifier {
        let key = DataKey::Admin;
        e.contract_data().get(key).unwrap().unwrap() // panics if there is no admin
    }

    pub fn get_iden(e: Env, id_key: BytesN<32>) -> Identity {
        let key = DataKey::Registered(id_key);
        e.contract_data().get(key).unwrap().unwrap()
    }

    pub fn write_iden(
        e: Env,
        id_key: BytesN<32>,
        name: Bytes,
        descr: Bytes,
        links: Vec<Link>,
        admin: Signature,
        nonce: BigInt,
    ) {
        let admin_id = admin.get_identifier(&e);
        check_auth(
            &e,
            &NonceForSignature(admin),
            nonce.clone(),
            symbol!("write_iden"),
            (&admin_id, nonce, id_key.clone()).into_val(&e),
        );

        let iden = Identity::new(name, descr, links, admin_id);
        let key = DataKey::Registered(id_key);
        e.contract_data().set(key, iden);
    }

    pub fn nonce(e: Env, id: Identifier) -> BigInt {
        read_nonce(&e, id)
    }
}
