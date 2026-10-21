use crate::{
    model::{DecodedInvoice, Network},
    money::{Decimal, Msat},
};
use bitcoin::hashes::{sha256, Hash};
use chrono::{DateTime, Utc};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef, Currency};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvoiceError {
    #[error("Invalid BOLT11 invoice")]
    Invalid,
    #[error("Invoice amount is out of range")]
    Amount,
    #[error("Invoice expired")]
    Expired,
    #[error("Invoice network does not match node")]
    Network,
    #[error("Invoice amount override is invalid")]
    Override,
    #[error("Invoice description hash does not match")]
    Description,
}

pub fn decode(
    bolt11: &str,
    node_network: Network,
    now: DateTime<Utc>,
) -> Result<DecodedInvoice, InvoiceError> {
    let invoice: Bolt11Invoice = bolt11.parse().map_err(|_| InvoiceError::Invalid)?;
    let network = match invoice.currency() {
        Currency::Bitcoin => Network::Mainnet,
        Currency::BitcoinTestnet => Network::Testnet,
        Currency::Regtest => Network::Regtest,
        Currency::Signet => Network::Signet,
        _ => Network::Unknown,
    };
    let expiry = invoice.expires_at().ok_or(InvoiceError::Invalid)?;
    let expires_at = DateTime::from_timestamp(
        i64::try_from(expiry.as_secs()).map_err(|_| InvoiceError::Invalid)?,
        0,
    )
    .ok_or(InvoiceError::Invalid)?;
    let (description, description_hash) = match invoice.description() {
        Bolt11InvoiceDescriptionRef::Direct(d) => (Some(d.to_string()), None),
        Bolt11InvoiceDescriptionRef::Hash(hash) => (None, Some(hash.0.to_string())),
    };
    Ok(DecodedInvoice {
        payment_hash: invoice.payment_hash().to_string(),
        network,
        network_matches_node: if node_network == Network::Unknown {
            None
        } else {
            Some(node_network == network)
        },
        destination: invoice.recover_payee_pub_key().to_string(),
        amount_msat: invoice
            .amount_milli_satoshis()
            .map(Decimal::new)
            .transpose()
            .map_err(|_| InvoiceError::Amount)?
            .map(Msat),
        requires_description: description_hash.is_some(),
        description,
        description_hash,
        expires_at,
        expired: now >= expires_at,
    })
}

pub fn validate_payment(
    decoded: &DecodedInvoice,
    override_amount: Option<Msat>,
    description: Option<&str>,
) -> Result<Msat, InvoiceError> {
    if decoded.expired {
        return Err(InvoiceError::Expired);
    }
    if decoded.network_matches_node != Some(true) {
        return Err(InvoiceError::Network);
    }
    let amount = match (decoded.amount_msat, override_amount) {
        (Some(amount), None) | (None, Some(amount)) => amount,
        _ => return Err(InvoiceError::Override),
    };
    amount.0.positive().map_err(|_| InvoiceError::Amount)?;
    match (&decoded.description_hash, description) {
        (Some(expected), Some(text))
            if sha256::Hash::hash(text.as_bytes()).to_string() == *expected => {}
        (None, None) => {}
        _ => return Err(InvoiceError::Description),
    }
    Ok(amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning_invoice::{InvoiceBuilder, PaymentSecret};
    use std::time::Duration;

    fn invoice(amount: Option<u64>, hashed_description: bool) -> String {
        let key = SecretKey::from_slice(&[42; 32]).unwrap();
        let builder = InvoiceBuilder::new(Currency::Regtest)
            .payment_hash(sha256::Hash::hash(&[43; 32]))
            .payment_secret(PaymentSecret([44; 32]))
            .duration_since_epoch(Duration::from_secs(1000))
            .expiry_time(Duration::from_secs(600))
            .min_final_cltv_expiry_delta(18);
        let builder = if let Some(amount) = amount {
            builder.amount_milli_satoshis(amount)
        } else {
            builder
        };
        let builder = if hashed_description {
            builder.description_hash(sha256::Hash::hash(b"description"))
        } else {
            builder.description("description".into())
        };
        builder
            .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &key))
            .unwrap()
            .to_string()
    }

    #[test]
    fn signed_invoice_keeps_msat_and_enforces_network_expiry_override() {
        let raw = invoice(Some(2500123), false);
        let now = DateTime::from_timestamp(1100, 0).unwrap();
        let decoded = decode(&raw, Network::Regtest, now).unwrap();
        assert_eq!(decoded.amount_msat.unwrap().0.get(), 2500123);
        assert_eq!(
            validate_payment(&decoded, None, None).unwrap().0.get(),
            2500123
        );
        assert_eq!(
            validate_payment(&decoded, Some(Msat(Decimal::new(1).unwrap())), None),
            Err(InvoiceError::Override)
        );
        let wrong = decode(&raw, Network::Mainnet, now).unwrap();
        assert_eq!(
            validate_payment(&wrong, None, None),
            Err(InvoiceError::Network)
        );
        let expired = decode(
            &raw,
            Network::Regtest,
            DateTime::from_timestamp(1600, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(
            validate_payment(&expired, None, None),
            Err(InvoiceError::Expired)
        );
        assert!(decode("lnbcrt-invalid", Network::Regtest, now).is_err());
    }

    #[test]
    fn amountless_and_description_hash_are_not_silently_guessed() {
        let raw = invoice(None, true);
        let decoded = decode(
            &raw,
            Network::Regtest,
            DateTime::from_timestamp(1100, 0).unwrap(),
        )
        .unwrap();
        let amount = Msat(Decimal::new(1001).unwrap());
        assert_eq!(
            validate_payment(&decoded, None, Some("description")),
            Err(InvoiceError::Override)
        );
        assert_eq!(
            validate_payment(&decoded, Some(amount), None),
            Err(InvoiceError::Description)
        );
        assert_eq!(
            validate_payment(&decoded, Some(amount), Some("wrong")),
            Err(InvoiceError::Description)
        );
        assert_eq!(
            validate_payment(&decoded, Some(amount), Some("description")),
            Ok(amount)
        );
    }
}
