use std::io;
use std::io::Write;

use rand::Rng;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero, ToPrimitive};
use num_integer::Integer;


const K: u64 = 16;
const SECURITY: u64 = 10;

fn is_probably_prime(n: &BigUint, k: u64) -> bool {
    if n <= &BigUint::from(3u64) {
        return *n == BigUint::from(2u64) || *n == BigUint::from(3u64);
    }
    if n % 2u64 == BigUint::zero() {
        return false;
    }

    // write n−1 as 2^r * d
    let mut d = n - 1u64;
    let mut r = 0;
    while &d % 2u64 == BigUint::zero() {
        d /= 2u64;
        r += 1;
    }

    let mut rng = rand::thread_rng();

    'witness_loop: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u64), &(n - 2u64));
        let mut x = a.modpow(&d, n);

        if x == One::one() || x == n - 1u64 {
            continue 'witness_loop;
        }

        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u64), n);
            if x == n - 1u64 {
                continue 'witness_loop;
            }
        }

        return false; // composite
    }

    true // probably prime
}

fn input(prompt: &str) -> Result<String, &str> {
    let mut s = String::new();
    print!("{prompt}");
    let _ = io::stdout().flush();
    match io::stdin().read_line(&mut s) {
        Ok(_) => {
            if let Some('\n')=s.chars().next_back() {
                s.pop();
            }
            if let Some('\r')=s.chars().next_back() {
                s.pop();
            }
            return Ok(s)
    },
        Err(_) => return Err("Failed to read line")
    }
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

fn generate_keys(size: u32) -> Option<(BigUint, BigUint, BigUint, BigUint, BigUint, BigUint)> {
    let mut rng = rand::thread_rng();
    let upper_bound = BigUint::one() * BigUint::from(10u32).pow(size);

    let p = loop {
        let num = rng.gen_biguint_below(&upper_bound);
        if is_probably_prime(&num, K) {
            break num;
        }
    };
    println!("got p");
    let q = loop {
        let num = rng.gen_biguint_below(&upper_bound);
        if is_probably_prime(&num, K) {
            break num;
        }
    };
    println!("got q");

    let n = &p * &q;
    println!("got n");
    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());
    println!("got phi_n");

    let e;
    let mut i = phi_n.clone();
    e = loop {
        if i < BigUint::from(2) {
            return None;
        }
        if &i % &p == BigUint::zero() || &i % &q == BigUint::zero() {
            continue;
        }
        if n.gcd(&i) == BigUint::one() && phi_n.gcd(&i) == BigUint::one() {
            break i;
        }
        i -= BigUint::one();
    };
    println!("got e");
    
    let mut i = &e + BigUint::one();
    let d = loop {
        if (&e * &i) % &phi_n == BigUint::one() {
            break i;
        }
        i += BigUint::one();
    };
    println!("got d");

    return Some((p, q, n, phi_n, e, d));
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

fn encrypt() {
    match input("What data to encrypt?\r\nNumber / Text / File [n/t/f]?> ").unwrap().to_lowercase().trim() {
        "n" => {
            match input("> ").unwrap().trim().parse::<u64>() {
                Ok(n) => {
                    println!("{}", n * 2 + 1);
                },
                Err(_) => println!("Not a number")
            };
        },
        _ => println!("Unknown action")
    }
}

fn main() {
    help(false);
    
    let mut keys = false;

    let mut p: BigUint = BigUint::zero();
    let mut q: BigUint = BigUint::zero();
    let mut n: BigUint = BigUint::zero();
    let mut phi_n: BigUint = BigUint::zero();
    let mut e: BigUint = BigUint::zero();
    let mut d: BigUint = BigUint::zero();

    loop {
        match input("\n[g/e/d/s/h/q]?> ").unwrap().to_lowercase().trim() {
            "g" => {
                match input("Enter key size (10^n) > ").unwrap().trim().parse::<u32>() {
                    Ok(size) => {
                        'security: loop {
                            match generate_keys(size) {
                                Some((p, q, n, phi_n, e, d)) => {
                                    let mut rng = rand::thread_rng();
                                    for _ in 0..SECURITY {
                                        let t: usize = rng.gen_range(1..10000);
                                        let c = encrypt_byte(t, &e, &n);
                                        let u = decrypt_byte(&c, &d, &n);
                                        if t != u {
                                            println!("Failed!!");
                                            continue 'security;
                                        }
                                    }

                                    keys = true;
                                    show(&p, &q, &n, &phi_n, &e, &d);

                                    break 'security;
                                },
                                None => continue 'security
                            }
                        }
                    },
                    Err(_) => println!("Not a number")
                }
            },
            "e" => {
                if keys {
                    encrypt();
                } else {
                    println!("Generate or input keys first");
                }
            },
            // "d" => decrypt(),
            "s" => show(&p, &q, &n, &phi_n, &e, &d),
            "h" => help(true),
            "q" => return,
            "" => {},
            _ => println!("Unknown action!")
        }
    }
}
