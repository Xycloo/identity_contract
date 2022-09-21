use soroban_auth::Identifier;
use soroban_sdk::{contracttype, Bytes, BytesN, Vec};

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
    pub fn new(name: Bytes, descr: Bytes, links: Vec<Link>, admin: Identifier) -> Self {
        Identity {
            name,
            descr,
            links,
            admin,
        }
    }
}
