// Copyright 2020 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use num_bigint::BigInt;
use num_traits::identities::{One, Zero};
use std::clone::Clone;

pub struct Util {}

impl Util {
    /// Finds the greatest common denominator of two integers *a* and *b*, and two
    /// integers *x* and *y* such that *ax* + *by* is the greatest common
    /// denominator of *a* and *b* (Bézout coefficients).
    ///
    /// This function is an implementation of the [extended Euclidean
    /// algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm).
    pub fn extend_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
        if a == BigInt::zero() {
            (b.clone(), BigInt::zero(), BigInt::one())
        } else {
            let (g, x, y) = Util::extend_gcd(b.clone() % a.clone(), a.clone());
            (g, y - (b.clone() / a.clone()) * x.clone(), x.clone())
        }
    }

    /// Calculates the [modular multiplicative
    /// inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) *x*
    /// of an integer *a* such that *ax* ≡ 1 (mod *m*).
    ///
    /// Such an integer may not exist. If so, this function will return `None`.
    /// Otherwise, the inverse will be returned wrapped up in a `Some`.
    pub fn mod_inverse(a: BigInt, modular: BigInt) -> Option<BigInt> {
        let (g, x, _) = Util::extend_gcd(a.clone(), modular.clone());
        if g != BigInt::one() {
            None
        } else {
            let result = (x.clone() % modular.clone() + modular.clone()) % modular.clone();
            Some(result)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_extend_gcd() {
        use super::BigInt;
        use super::One;
        use super::Util;
        let a = BigInt::from(26);
        let b = BigInt::from(3);
        let (g, x, y) = Util::extend_gcd(a.clone(), b.clone());

        assert_eq!(g, BigInt::one());
        assert_eq!(x, BigInt::from(-1));
        assert_eq!(y, BigInt::from(9));
        assert_eq!((a.clone() * x) + (b.clone() * y), g);
    }

    #[test]
    fn test_mod_inverse() {
        use super::BigInt;
        use super::Util;

        // 3*inverse = 1 mod 26
        let does_exist = Util::mod_inverse(BigInt::from(3), BigInt::from(26));
        // 4*inverse = 1 mod 32
        let does_not_exist = Util::mod_inverse(BigInt::from(4), BigInt::from(32));

        match does_exist {
            Some(x) => assert_eq!(x, BigInt::from(9)),
            None => panic!("mod_inverse() didn't work as expected"),
        }

        match does_not_exist {
            Some(x) => {
                drop(x);
                panic!("mod_inverse() found an inverse when it shouldn't have")
            }
            None => {}
        }
    }
}
