// Copyright 2020-2021 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use num_bigint::{BigInt, Sign};
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
    pub fn mod_inverse(a: &BigInt, modular: &BigInt) -> Option<BigInt> {
        let (g, x, _) = Util::extend_gcd(a.clone(), modular.clone());
        if g != BigInt::one() {
            None
        } else {
            let result = (x.clone() % modular.clone() + modular.clone()) % modular.clone();
            Some(result)
        }
    }

    /// returned (numerator: BigInt, denominator: BigInt) represent as  numerator/denominator
    ///
    /// where λ_i= ∏ j≠i = j/(j−i) is a Lagrange coefficient.
    /// 1 <= i <= threshold  0 <= j < threshold
    pub fn lagrange_coefficient(i: &i64, values: &[i64]) -> (BigInt, BigInt) {
        if !values.contains(i) {
            return (BigInt::zero(), BigInt::one());
        }

        let mut numerator = BigInt::one();
        let mut denominator = BigInt::one();

        let vec_to = values.to_vec();
        let max = vec_to.iter().max().unwrap();
        for j in 1..=*max {
            if j != *i && values.contains(&j) {
                numerator = numerator * j;
                denominator = denominator * (j - *i);
            }
        }
        return (numerator, denominator);
    }

    /// return abs value
    pub fn abs(n: &BigInt) -> BigInt {
        match n.sign() {
            Sign::Minus => BigInt::new(Sign::Plus, n.to_u32_digits().1),
            Sign::Plus => n.clone(),
            Sign::NoSign => n.clone(),
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
        let does_exist = Util::mod_inverse(&BigInt::from(3), &BigInt::from(26));
        // 4*inverse = 1 mod 32
        let does_not_exist = Util::mod_inverse(&BigInt::from(4), &BigInt::from(32));

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

    #[test]
    fn test_lagrange_coefficient() {
        use super::BigInt;
        use super::Util;
        use super::{One, Zero};

        let i_array = [9, 1, 2, 3];
        let values = [0, 1, 2, 3, 4, 5, 6];
        let result = Util::lagrange_coefficient(&i_array[0], &values);
        assert_eq!(result, (BigInt::zero(), BigInt::one()));

        // 0..=6 j/(j-1) = (2/1) * (3/2) * (4/3) * (5/4) * (6/5) = 720 / 120
        let result = Util::lagrange_coefficient(&i_array[1], &values);
        assert_eq!(result, (BigInt::from(720), BigInt::from(120)));

        // 0..=6 j/(j-2) =  (1/-1) * (3/1) * (4/2) * (5/3) * (6/4) = 360 / -24
        let result = Util::lagrange_coefficient(&i_array[2], &values);
        assert_eq!(result, (BigInt::from(360), BigInt::from(-24)));

        // 0..=6 j/(j-3) =  (1/-2) * (2/-1) * (4/1) * (5/2) * (6/3) = 240 / 12
        let result = Util::lagrange_coefficient(&i_array[3], &values);
        assert_eq!(result, (BigInt::from(240), BigInt::from(12)));
    }

    #[test]
    fn test_abs() {
        use super::BigInt;
        use super::Util;
        let minus = BigInt::from(-100);
        assert_eq!(Util::abs(&minus), BigInt::from(100));

        let minus = BigInt::from(-0);
        assert_eq!(Util::abs(&minus), BigInt::from(0));

        let plus = BigInt::from(0);
        assert_eq!(Util::abs(&plus), BigInt::from(0));

        let plus = BigInt::from(100);
        assert_eq!(Util::abs(&plus), BigInt::from(100));
    }
}
