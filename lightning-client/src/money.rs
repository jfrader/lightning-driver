use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct Decimal(u64);

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
#[error("Expected a canonical nonnegative integer no greater than i64::MAX")]
pub struct InvalidAmount;

impl Decimal {
    pub const ZERO: Self = Self(0);

    pub fn new(value: u64) -> Result<Self, InvalidAmount> {
        i64::try_from(value).map_err(|_| InvalidAmount)?;
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, InvalidAmount> {
        Self::new(self.0.checked_add(other.0).ok_or(InvalidAmount)?)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, InvalidAmount> {
        Self::new(self.0.checked_sub(other.0).ok_or(InvalidAmount)?)
    }

    pub fn checked_mul(self, factor: u64) -> Result<Self, InvalidAmount> {
        Self::new(self.0.checked_mul(factor).ok_or(InvalidAmount)?)
    }

    pub fn positive(self) -> Result<Self, InvalidAmount> {
        if self == Self::ZERO {
            Err(InvalidAmount)
        } else {
            Ok(self)
        }
    }
}

impl FromStr for Decimal {
    type Err = InvalidAmount;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(InvalidAmount);
        }
        Self::new(s.parse().map_err(|_| InvalidAmount)?)
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sat(pub Decimal);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Msat(pub Decimal);

impl Sat {
    pub fn to_msat(self) -> Result<Msat, InvalidAmount> {
        Ok(Msat(self.0.checked_mul(1000)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_strings_and_checked_units() {
        for s in [
            "",
            "00",
            "+1",
            "-1",
            "1.0",
            "1e3",
            "1\n",
            " 1",
            "9223372036854775808",
        ] {
            assert!(s.parse::<Decimal>().is_err(), "accepted {s:?}");
        }
        for s in ["0", "1", "9007199254740993", "9223372036854775807"] {
            let amount: Decimal = s.parse().unwrap();
            assert_eq!(serde_json::to_string(&amount).unwrap(), format!("\"{s}\""));
            assert_eq!(
                serde_json::from_str::<Decimal>(&format!("\"{s}\"")).unwrap(),
                amount
            );
        }
        assert!(serde_json::from_str::<Decimal>("1").is_err());
        assert!(Decimal::ZERO.positive().is_err());
        assert!("9223372036854775807"
            .parse::<Decimal>()
            .unwrap()
            .checked_add(Decimal::new(1).unwrap())
            .is_err());
        assert!(Sat("9223372036854776".parse().unwrap()).to_msat().is_err());
        assert_eq!(
            Sat(Decimal::new(123).unwrap()).to_msat().unwrap(),
            Msat(Decimal::new(123000).unwrap())
        );
    }
}
