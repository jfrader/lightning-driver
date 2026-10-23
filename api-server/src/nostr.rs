use crate::auth::AuthError;
use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const TTL_SECONDS: i64 = 120;
pub const MAX_IDENTITIES: i64 = 8;
pub const MAX_ATTEMPTS: i64 = 5;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub pubkey: String,
    pub id: String,
    pub sig: String,
    pub kind: u32,
    pub created_at: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

pub fn normalize_pubkey(value: &str) -> Result<String, AuthError> {
    let bytes = hex::decode(value).map_err(|_| AuthError::Authentication)?;
    if bytes.len() != 32 {
        return Err(AuthError::Authentication);
    }
    XOnlyPublicKey::from_slice(&bytes).map_err(|_| AuthError::Authentication)?;
    Ok(hex::encode(bytes))
}

impl Event {
    pub fn computed_id(&self) -> Result<[u8; 32], AuthError> {
        let bytes = serde_json::to_vec(&serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]))
        .map_err(|_| AuthError::Authentication)?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn verify_signature(&self) -> Result<String, AuthError> {
        let key = normalize_pubkey(&self.pubkey)?;
        let id = self.computed_id()?;
        let supplied = hex::decode(&self.id).map_err(|_| AuthError::Authentication)?;
        if self.id != self.id.to_ascii_lowercase() || !bool::from(id.ct_eq(&supplied)) {
            return Err(AuthError::Authentication);
        }
        let signature =
            Signature::from_slice(&hex::decode(&self.sig).map_err(|_| AuthError::Authentication)?)
                .map_err(|_| AuthError::Authentication)?;
        let public =
            XOnlyPublicKey::from_slice(&hex::decode(&key).map_err(|_| AuthError::Authentication)?)
                .map_err(|_| AuthError::Authentication)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &Message::from_digest(id), &public)
            .map_err(|_| AuthError::Authentication)?;
        Ok(key)
    }

    pub fn verify(
        &self,
        expected: &[Vec<String>],
        nonce_hash: &[u8],
        now: i64,
    ) -> Result<String, AuthError> {
        if self.kind != 27235
            || !self.content.is_empty()
            || self.created_at.abs_diff(now) > TTL_SECONDS as u64
            || self.tags.len() != expected.len()
        {
            return Err(AuthError::Authentication);
        }
        for tag in expected {
            let matching: Vec<_> = self
                .tags
                .iter()
                .filter(|t| t.first() == tag.first())
                .collect();
            if matching.len() != 1 || matching[0].len() != 2 {
                return Err(AuthError::Authentication);
            }
            if tag[0] == "challenge" {
                let nonce = &matching[0][1];
                if nonce.len() != 64
                    || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
                    || !bool::from(Sha256::digest(nonce.as_bytes())[..].ct_eq(nonce_hash))
                {
                    return Err(AuthError::Authentication);
                }
            } else if !bool::from(matching[0][1].as_bytes().ct_eq(tag[1].as_bytes())) {
                return Err(AuthError::Authentication);
            }
        }
        self.verify_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_nostr_tools_vector() {
        let event: Event = serde_json::from_value(serde_json::json!({
            "pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "id":"42f3476a5d80f28681144d0899d4dc8417cacde2d4fd8a3914f2aa5cc2a116a2",
            "sig":"55f0d4e80c7c9dfca465c70b18f3d2cb415a7818190b775afc79034034eeb5b5a27c18c617df28e1eb451c6f7c2cd91d8fcbe713e34809f497002c72ae13494e",
            "kind":27235,"created_at":1770000000,"content":"",
            "tags":[["u","https://manager.example.invalid/api/v1/auth/nostr/finish"],["method","POST"],["challenge","0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],["purpose","login"]]
        })).unwrap();
        assert_eq!(hex::encode(event.computed_id().unwrap()), event.id);
        event.verify_signature().unwrap();
    }
}
