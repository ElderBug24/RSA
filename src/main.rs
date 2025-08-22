use std::io;
use std::io::Write;
use std::str::FromStr;
use std::time::Instant;

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
        println!("i: Input keys / initial numbers to generate the keys");
        println!("e: Encrypt data");
        println!("d: Decrypt data");
        println!("s: Show saved variables");
        println!("h: Show this help");
        println!("q: Quit");
    }
}

fn generate_keys_(size: u32, c: Option<(&BigUint, &BigUint)>) -> Option<(BigUint, BigUint, BigUint, BigUint, BigUint, BigUint)> {
    let mut rng = rand::thread_rng();

    let p: BigUint;
    let q: BigUint;

    match c {
        Some((p_, q_)) => {
            p = p_.clone();
            q = q_.clone();
        },
        None => {
            let upper_bound = BigUint::one() * BigUint::from(10u64).pow(size);
            p = loop {
                let num = rng.gen_biguint_below(&upper_bound);
                if is_probably_prime(&num, K) {
                    break num;
                }
            };
            q = loop {
                let num = rng.gen_biguint_below(&upper_bound);
                if is_probably_prime(&num, K) {
                    break num;
                }
            };
        }
    }

    let n = &p * &q;
    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

    let e;
    let mut i = phi_n.clone();
    e = loop {
        if i < BigUint::from(2u64) {
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
    
    let mut i = &e + BigUint::one();
    let d = loop {
        if (&e * &i) % &phi_n == BigUint::one() {
            break i;
        }
        i += BigUint::one();
    };

    return Some((p, q, n, phi_n, e, d));
}

fn generate_keys(size: u32, c: Option<(&BigUint, &BigUint)>) -> (BigUint, BigUint, BigUint, BigUint, BigUint, BigUint) {
    'security: loop {
        match generate_keys_(size, c) {
            Some((p, q, n, phi_n, e, d)) => {
                let mut rng = rand::thread_rng();
                for _ in 0..SECURITY {
                    let t: u64 = rng.gen_range(1..10000);
                    let c = encrypt_byte(t, &e, &n);
                    let u = decrypt_byte(&c, &d, &n);
                    if t != u {
                        println!("Failed!!");
                        continue 'security;
                    }
                }

                break 'security (p, q, n, phi_n, e, d);
            },
            None => continue 'security
        }
    }

}

fn show(keys: Option<(&BigUint, &BigUint, &BigUint)>, c: Option<(&BigUint, &BigUint, &BigUint)>, data: &String, encrypted_data: &Vec<BigUint>) {
    if let Some((ref p, ref q, ref phi_n)) = c {
        println!("p: {p}");
        println!("q: {q}");
        println!("Phi(N): {phi_n}");
    }
    if let Some((ref n, ref e, ref d)) = keys {
        println!("e: {e}");
        println!("d: {d}");
        println!("N: {n}");
    }
    
    println!("Data: {data:?}");
    println!("Encrypted Data: {encrypted_data:?}");

}

fn encrypt_byte(data: u64, e: &BigUint, n: &BigUint) -> BigUint {
    let b = BigUint::from(data);
    return b.modpow(&e, &n);
}

fn decrypt_byte(data: &BigUint, d: &BigUint, n: &BigUint) -> u64 {
    let b: u64 = data.modpow(&d, &n).to_u64().unwrap();
    return b;
}

fn encrypt_data(data: Vec<u64>) -> Vec<BigUint> {
    let encrypted_data: Vec<BigUint> = Vec::with_capacity(data.len());

    return encrypted_data;
}

fn encrypt(e: &BigUint, n: &BigUint) -> Result<(u64, Vec<BigUint>), &'static str> {
    match input("What data to encrypt?\r\nNumber(s) / Text / File [n/t/f]?> ").unwrap().to_lowercase().trim() {
        "n" => {
            let numbers_text = input("> ").unwrap().trim();
            let data: Vec<u64> = Vec::new();

            s = 0
            for i in 0..numbers_text.len() {
                if 
            }

            match input("> ").unwrap().trim().parse::<u64>() {
                Ok(num) => {
                    return Ok((num, encrypt_byte(num, &e, &n)));
                },
                Err(_) => return Err("Not a number")
            };
        },
        _ => return Err("Unknown action")
    }
}

fn decrypt(encrypted_scalar_data: &BigUint, encrypted_data: &Vec<BigUint>, d: &BigUint, n: &BigUint) -> Result<u64, &'static str> {
    match input("What data to decrypt?\r\nScalar / Array [s/a]?> ").unwrap().to_lowercase().trim() {
        "s" => {
            return Ok(decrypt_byte(encrypted_scalar_data, &e, &n));
        },
        _ => return Err("Unknown action")
    }
}

fn main() {
    help(false);
    
    let mut keys = false;
    let mut c = false;
    let mut data_is_text = false;

    let mut p = BigUint::zero();
    let mut q = BigUint::zero();
    let mut n = BigUint::zero();
    let mut phi_n = BigUint::zero();
    let mut e = BigUint::zero();
    let mut d = BigUint::zero();

    let mut data = Vec::new();
    let mut encrypted_data: Vec<BigUint> = Vec::new();

    loop {
        match input("\n[g/i/e/d/s/h/q]?> ").unwrap().to_lowercase().trim() {
            "g" => {
                match input("Enter key size (10^n) > ").unwrap().trim().parse::<u32>() {
                    Ok(size) => {
                        let start = Instant::now();

                        (p, q, n, phi_n, e, d) = generate_keys(size, None);

                        keys = true;
                        c = true;

                        show({if keys {
                                  Some((&n, &e, &d))
                              } else { None }},
                              {if c {
                                  Some((&p, &q, &phi_n))
                              } else { None }}, scalar_data, &data, &encrypted_scalar_data, &encrypted_data);

                        println!("Done in {:.3?}", start.elapsed())
                    },
                    Err(_) => println!("Not a number")
                }
            },
            "i" => {
                match input("Input Keys or Initial numbers [k/i]?> ").unwrap().to_lowercase().trim() {
                    "k" => {
                        match BigUint::from_str(&input("e > ").unwrap()) {
                            Ok(e_) => e = e_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }
                        match BigUint::from_str(&input("d > ").unwrap()) {
                            Ok(d_) => d = d_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }
                        match BigUint::from_str(&input("N > ").unwrap()) {
                            Ok(n_) => n = n_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }

                        keys = true;
                        c = false;
                    },
                    "i" => {
                        match BigUint::from_str(&input("p > ").unwrap()) {
                            Ok(p_) => p = p_,
                            Err(_) => {
                                println!("Not a number");
                            }
                        }
                        match BigUint::from_str(&input("q > ").unwrap()) {
                            Ok(q_) => q = q_,
                            Err(_) => {
                                println!("Not a number");
                            }
                        }

                        c = true;
                        generate_keys(0u32, Some((&p, &q)));
                        keys = true;
                    }
                    _ => println!("Unknown action")
                }
            },
            "e" => {
                if keys {
                    match encrypt(&e, &n) {
                        Ok((data_, encrypted_data_)) => {
                            data = data_;
                            encrypted_data = encrypted_data_.clone();
                            println!("{}", data);
                            println!("{}", encrypted_data);
                        },
                        Err(e) => println!("{e}")
                    }
                } else {
                    println!("Generate or input keys first");
                }
            },
            // "d" => decrypt(),
            "s" => show({if keys {
                           Some((&n, &e, &d))
                       } else { None }},
                       {if c {
                           Some((&p, &q, &phi_n))
                       } else { None }}, &data, &encrypted_data),
            "h" => help(true),
            "q" => return,
            "" => {},
            _ => println!("Unknown action!")
        }
    }
}
