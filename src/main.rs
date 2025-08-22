use std::io;

use rand::Rng;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero, ToPrimitive};
use num_integer::Integer;


const K: u32 = 4;
const SECURITY: u32 = 10;

fn is_probably_prime(n: &BigUint, k: u32) -> bool {
    if n <= &BigUint::from(3u32) {
        return *n == BigUint::from(2u32) || *n == BigUint::from(3u32);
    }
    if n % 2u32 == BigUint::zero() {
        return false;
    }

    // write n−1 as 2^r * d
    let mut d = n - 1u32;
    let mut r = 0;
    while &d % 2u32 == BigUint::zero() {
        d /= 2u32;
        r += 1;
    }

    let mut rng = rand::thread_rng();

    'witness_loop: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - 2u32));
        let mut x = a.modpow(&d, n);

        if x == One::one() || x == n - 1u32 {
            continue 'witness_loop;
        }

        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n - 1u32 {
                continue 'witness_loop;
            }
        }

        return false; // composite
    }

    true // probably prime
}

fn help(verbose: bool) {
    println!("RSA asymetrical data encryption");
    if verbose {
        println!("g: Generate keys");
        println!("e: Encrypt data");
        println!("d: Decrypt data");
        println!("s: Show saved variables");
        println!("h: Show this help");
        println!("q: Quit");
    }
}

fn generate_keys() -> Result<(BigUint, BigUint, BigUint, BigUint, BigUint, BigUint), &'static str> {
    println!("Enter key size (10^n)");
    let mut size = String::new();

    io::stdin().read_line(&mut size).expect("Failed to read line");

    match size.trim().parse() {
        Ok(size) => {
            let mut rng = rand::thread_rng();
            let upper_bound = BigUint::one() * BigUint::from(10u32).pow(size);

            let p = loop {
                let num = rng.gen_biguint_below(&upper_bound);
                if is_probably_prime(&num, K) {
                    break num;
                }
            };
            let q = loop {
                let num = rng.gen_biguint_below(&upper_bound);
                if is_probably_prime(&num, K) {
                    break num;
                }
            };

            let n = &p * &q;
            let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

            let e;
            let mut i = phi_n.clone();
            e = loop {
                if &i % &p == BigUint::zero() || &i % &q == BigUint::zero() {
                    continue
                }
                if n.gcd(&i) == BigUint::one() && phi_n.gcd(&i) == BigUint::one() {
                    break i;
                }
                i -= BigUint::one();
            };
            
            let mut i = &e + BigUint::one();
            let d = loop {
                if (&e * &i) % &phi_n == BigUint::one() {
                    break i;
                }
                i += BigUint::one();
            };

            return Ok((p, q, n, phi_n, e, d));
        },
        Err(_) => return Err("Not a number")
    };
}

fn show(p: &BigUint, q: &BigUint, n: &BigUint, phi_n: &BigUint, e: &BigUint, d: &BigUint) {
    println!("p: {p}");
    println!("q: {q}");
    println!("N: {n}");
    println!("Phi(N): {phi_n}");
    println!("e: {e}");
    println!("d: {d}");
}

fn encrypt_byte(data: usize, e: &BigUint, n: &BigUint) -> BigUint {
    let b = BigUint::from(data);
    b.modpow(&e, &n)
}

fn decrypt_byte(data: &BigUint, d: &BigUint, n: &BigUint) -> usize {
    let b: usize = data.modpow(&d, &n).to_usize().unwrap();
    b
}

fn main() {
    help(false);

    let mut input = String::new();

    let mut p: BigUint = BigUint::zero();
    let mut q: BigUint = BigUint::zero();
    let mut n: BigUint = BigUint::zero();
    let mut phi_n: BigUint = BigUint::zero();
    let mut e: BigUint = BigUint::zero();
    let mut d: BigUint = BigUint::zero();

    loop {
        println!();
        println!("[g/e/d/s/h/q]");

        input.clear();
        io::stdin().read_line(&mut input).expect("Failed to read line");

        match input.to_lowercase().trim() {
            "g" => {
                'security: loop {
                    match generate_keys() {
                        Ok(result) => {
                            (p, q, n, phi_n, e, d) = result;
                            show(&p, &q, &n, &phi_n, &e, &d);

                            let mut rng = rand::thread_rng();

                            for _ in 0..SECURITY {
                                let t: usize = rng.gen_range(1..10000);
                                let c = encrypt_byte(t, &e, &n);
                                let u = decrypt_byte(&c, &d, &n);
                                if t != u {
                                    println!("Failed!!");
                                    continue 'security;
                                }
                            };

                            break;
                        },
                        Err(e) => println!("{e}")
                    };
                };
                
            },
            // "e" => encrypt(),
            // "d" => decrypt(),
            "s" => show(&p, &q, &n, &phi_n, &e, &d),
            "h" => help(true),
            "q" => return,
            _ => println!("Unknown action!")
        }
    }
}
