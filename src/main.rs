use std::io;
use std::io::Write;
use std::str::FromStr;
use std::time::Instant;

use rand::Rng;
use num_bigint::{BigUint, RandBigInt, BigInt, ToBigInt, ToBigUint};
use num_traits::{One, Zero, ToPrimitive, Signed};
use num_integer::Integer;


const K: u32 = 16;
const SECURITY: u32 = 10;


struct Context {
    keys: bool,
    c: bool,
    data_is_text: bool,
    p: BigUint,
    q: BigUint,
    n: BigUint,
    phi_n: BigUint,
    e: BigUint,
    d: BigUint,
    data: Vec<u32>,
    encrypted_data: Vec<BigUint>
}


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
    } else {
        println!("Type 'h' for help")
    }
}

fn test_keys(context: &Context) -> bool {
    let mut rng = rand::thread_rng();
    let mut failed = false;

    for _ in 0..SECURITY {
        let num = rng.gen_range(2..u32::MAX);
        let numv = vec![num];
        let e_numv = encrypt_data(&numv, &context.e, &context.n);
        let d_num = decrypt_data(&e_numv, &context.d, &context.n)[0];

        failed |= num == d_num;
    }

    return failed;
}

fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a = a.to_bigint().unwrap();
    let m = m.to_bigint().unwrap();

    let mut mn = (m.clone(), a.clone());
    let mut xy = (BigInt::zero(), BigInt::one());

    while mn.1 != BigInt::zero() {
        let q = &mn.0 / &mn.1;
        mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
        xy = (xy.1.clone(), &xy.0 - &q * &xy.1);
    }

    if mn.0 != BigInt::one() {
        return None; // no inverse
    }

    // make sure result is positive
    while xy.0 < BigInt::zero() {
        xy.0 += &m;
    }

    return Some(xy.0.to_biguint().unwrap());
}

// fn egcd(mut a: BigInt, mut b: BigInt) -> (BigInt, BigInt, BigInt) {
//     let (mut x0, mut x1) = (BigInt::one(), BigInt::zero());
//     let (mut y0, mut y1) = (BigInt::zero(), BigInt::one());
//
//     while !b.is_zero() {
//         let q = &a / &b;
//
//         // (a, b) <- (b, a - q*b)
//         let tmp_a = b.clone();
//         b = &a - &q * &b;
//         a = tmp_a;
//
//         // (x0, x1) <- (x1, x0 - q*x1)
//         let tmp_x = x1.clone();
//         x1 = &x0 - &q * &x1;
//         x0 = tmp_x;
//
//         // (y0, y1) <- (y1, y0 - q*y1)
//         let tmp_y = y1.clone();
//         y1 = &y0 - &q * &y1;
//         y0 = tmp_y;
//     }
//     (a, x0, y0)
// }
//
// /// Modular inverse for BigUint: returns Some(a^{-1} mod m) or None if not invertible
// fn modinv_biguint(a: &BigUint, m: &BigUint) -> Option<BigUint> {
//     if m.is_zero() { return None; }
//     let a_i = a.to_bigint().unwrap();
//     let m_i = m.to_bigint().unwrap();
//
//     let (g, x, _) = egcd(a_i, m_i.clone());
//     if g != BigInt::one() {
//         return None; // not coprime, no inverse exists
//     }
//     // x may be negative; normalize into [0, m)
//     let mut x = x % &m_i;
//     if x.is_negative() { x += &m_i; }
//     x.to_biguint()
// }

fn generate_keys(context: &mut Context, size: u32, c: bool) {
    let mut rng = rand::thread_rng();

    let p: BigUint;
    let q: BigUint;

    if c {
        let upper_bound = BigUint::one() * BigUint::from(10u32).pow(size);
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
    } else {
        p = context.p.clone();
        q = context.q.clone();
    }

    let n = &p * &q;
    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

    /*
    // let mut i = phi_n.clone();
    let mut e = BigUint::from(2u32);
    e = loop {
        // if e < BigUint::from(2u32) {
        // if e == phi_n {
        //     panic!("kaboom");
        // }
        if &e % &p == BigUint::zero() || &e % &q == BigUint::zero() {
            continue;
        }
        if n.gcd(&e) == BigUint::one() && phi_n.gcd(&e) == BigUint::one() {
            break e;
        }
        // e -= BigUint::one();
        // e += BigUint::one();
        e = rng.gen_biguint_below(&phi_n);
    };
    */

    let e = BigUint::from(65537u32);

    let d = modinv(&e, &phi_n).unwrap();

    /*
    // let mut d = &e + BigUint::one();
    let mut d = BigUint::one();
    d = loop {
        if (&e * &d) % &phi_n == BigUint::one() {
            break d;
        }
        // d += BigUint::one();
        d += rng.gen_biguint_below(&phi_n);
    };
    */

    context.p = p;
    context.q = q;
    context.n = n;
    context.phi_n = phi_n;
    context.e = e;
    context.d = d;

    if !test_keys(&context) {
        panic!("Failed!");
    }
}

fn show(context: &Context) {
    if context.c {
        println!("p: {}", context.p);
        println!("q: {}", context.q);
        println!("Phi(N): {}", context.phi_n);
    }
    if context.keys {
        println!("e: {}", context.e);
        println!("d: {}", context.d);
        println!("N: {}", context.n);
    }
    
    println!("Data: {:?}", context.data);
    println!("Encrypted Data: {:?}", context.encrypted_data);

}

fn encrypt_byte(data: u8, e: &BigUint, n: &BigUint) -> BigUint {
    let b = BigUint::from(data);
    return b.modpow(&e, &n);
}

fn decrypt_byte(data: &BigUint, d: &BigUint, n: &BigUint) -> u8 {
    let b: u8 = data.modpow(&d, &n).to_u8().unwrap();
    return b;
}

fn encrypt_data(data: &Vec<u32>, e: &BigUint, n: &BigUint) -> Vec<BigUint> {
    let mut encrypted_data: Vec<BigUint> = Vec::with_capacity(data.len() * 4);
    
    for num in data {
        let num = num.to_be_bytes();
        for b in num {
            encrypted_data.push(encrypt_byte(b, &e, &n));
        }
    }

    return encrypted_data;
}

fn decrypt_data(encrypted_data: &Vec<BigUint>, d: &BigUint, n: &BigUint) -> Vec<u32> {
    let mut data: Vec<u32> = Vec::with_capacity(encrypted_data.len() / 4);
    
    for i in 0..data.capacity() {
        let e_num = &encrypted_data[(i*4)..((i+1)*4)];
        let mut num = [0u8; 4];
        for i in 0..4 {
            num[i] = decrypt_byte(&e_num[i], &d, &n);
        }
        data.push(u32::from_be_bytes(num));
    }

    return data;
}

// fn encrypt(e: &BigUint, n: &BigUint) -> Result<(u32, Vec<BigUint>), &'static str> {
//     match input("What data to encrypt?\r\nNumber(s) / Text / File [n/t/f]?> ").unwrap().to_lowercase().trim() {
//         "n" => {
//             // let numbers_text = input("> ").unwrap().trim();
//             // let data: Vec<u32> = Vec::new();
//             //
//             // s = 0;
//             // for i in 0..numbers_text.len() {
//             //     if 
//             // }
//
//             match input("> ").unwrap().trim().parse::<u32>() {
//                 Ok(num) => {
//                     return Ok((num, encrypt_byte(num, &e, &n)));
//                 },
//                 Err(_) => return Err("Not a number")
//             };
//         },
//         _ => return Err("Unknown action")
//     }
// }

// fn decrypt(encrypted_scalar_data: &BigUint, encrypted_data: &Vec<BigUint>, d: &BigUint, n: &BigUint) -> Result<u32, &'static str> {
//     match input("What data to decrypt?\r\nScalar / Array [s/a]?> ").unwrap().to_lowercase().trim() {
//         "s" => {
//             return Ok(decrypt_byte(encrypted_scalar_data, &e, &n));
//         },
//         _ => return Err("Unknown action")
//     }
// }

fn main() {
    help(false);

    let mut context = Context {
        keys: false,
        c: false,
        data_is_text: false,
        p: BigUint::zero(),
        q: BigUint::zero(),
        n: BigUint::zero(),
        phi_n: BigUint::zero(),
        e: BigUint::zero(),
        d: BigUint::zero(),
        data: Vec::new(),
        encrypted_data: Vec::new()
    };

    loop {
        match input("\n[g/i/e/d/s/h/q]?> ").unwrap().to_lowercase().trim() {
            "g" => {
                match input("Enter key size (10^n) > ").unwrap().trim().parse::<u32>() {
                    Ok(size) => {
                        let start = Instant::now();

                        generate_keys(&mut context, size, true);

                        context.keys = true;
                        context.c = true;
                        show(&context);

                        println!("Done in {:.3?}", start.elapsed());
                    },
                    Err(_) => println!("Not a number")
                }
            },
            "i" => {
                match input("Input Keys or Initial numbers [k/i]?> ").unwrap().to_lowercase().trim() {
                    "k" => {
                        match BigUint::from_str(&input("e > ").unwrap()) {
                            Ok(e_) => context.e = e_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }
                        match BigUint::from_str(&input("d > ").unwrap()) {
                            Ok(d_) => context.d = d_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }
                        match BigUint::from_str(&input("N > ").unwrap()) {
                            Ok(n_) => context.n = n_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }

                        context.keys = true;
                        context.c = false;
                    },
                    "i" => {
                        match BigUint::from_str(&input("p > ").unwrap()) {
                            Ok(p_) => context.p = p_,
                            Err(_) => {
                                println!("Not a number");
                            }
                        }
                        match BigUint::from_str(&input("q > ").unwrap()) {
                            Ok(q_) => context.q = q_,
                            Err(_) => {
                                println!("Not a number");
                            }
                        }

                        context.c = true;
                        generate_keys(&mut context, 0u32, false);
                        context.keys = true;
                    }
                    _ => println!("Unknown action")
                }
            },
            // "e" => {
            //     if keys {
            //         match encrypt(&e, &n) {
            //             Ok((data_, encrypted_data_)) => {
            //                 data = data_;
            //                 encrypted_data = encrypted_data_.clone();
            //                 println!("{}", data);
            //                 println!("{}", encrypted_data);
            //             },
            //             Err(e) => println!("{e}")
            //         }
            //     } else {
            //         println!("Generate or input keys first");
            //     }
            // },
            // "d" => decrypt(),
            "s" =>  show(&context),
            "h" => help(true),
            "q" => return,
            "" => {},
            _ => println!("Unknown action!")
        }
    }
}
