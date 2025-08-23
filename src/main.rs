use std::io;
use std::io::Write;
use std::str::FromStr;
use std::time::Instant;

use rand::Rng;
use num_bigint::{BigUint, RandBigInt, BigInt, ToBigInt};
use num_traits::{One, Zero, ToPrimitive};
use num_integer::Integer;


const K: u32 = 64;
const SECURITY: u32 = 32;


struct Context {
    keys: bool,
    c: bool,
    data_is_text: bool,
    decrypted_data_is_text: bool,
    p: BigUint,
    q: BigUint,
    n: BigUint,
    phi_n: BigUint,
    e: BigUint,
    d: BigUint,
    data: Vec<u32>,
    encrypted_data: Vec<BigUint>,
    decrypted_data: Vec<u32>
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
    println!();
    println!("RSA asymetrical data encryption");
    if verbose {
        println!();
        println!("g: Generate keys");
        println!("i: Input keys / initial numbers to generate the keys");
        println!("e: Encrypt data");
        println!("d: Decrypt data");
        println!("s: Show saved variables");
        println!("o: Output encrypted or decrypted data");
        println!("h: Show this help");
        println!("q: Quit");
    } else {
        println!();
        println!("Type 'h' for help");
    }
}

fn test_keys(context: &Context) -> bool {
    let mut rng = rand::thread_rng();
    let mut failed = false;

    let mut random: Box<dyn FnMut() -> u32> = if &context.n <= &BigUint::from(u32::MAX) {
        Box::new(move || rng.gen_biguint_below(&context.phi_n).to_u32().unwrap())
    } else {
        Box::new(move || rng.gen_range(2..u32::MAX))
    };

    for _ in 0..SECURITY {
        let num1 = random();
        let num2 = random();
        let numv = vec![num1, num2];
        let e_numv = encrypt_data(&numv, &context.e, &context.n);
        let d_nums = decrypt_data(&e_numv, &context.d, &context.n);

        failed |= num1 != d_nums[0];
        failed |= num2 != d_nums[1];
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

    let e = BigUint::from( if phi_n > BigUint::from(65537u32) {
        65537u32
    } else {
        let mut i = 2;
        loop {
            if n.gcd(&BigUint::from(i)) == BigUint::one() && phi_n.gcd(&BigUint::from(i)) == BigUint::one() {
                break i;
            }
            i = rng.gen_range(2..phi_n.to_u32().unwrap());
        }
    } );

    let mut d = modinv(&e, &phi_n).unwrap();
    if d == e {
        d += &phi_n;
    }

    context.p = p;
    context.q = q;
    context.n = n;
    context.phi_n = phi_n;
    context.e = e;
    context.d = d;

    if test_keys(&context) {
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

    println!("Data: {}", if context.data_is_text { format!("{:?}", context.data.iter().map(|&code| char::from_u32(code).unwrap()).collect::<String>()) } else { format!("{:?}", context.data) });
    println!("Encrypted Data: {:?}", context.encrypted_data);
    println!("Decrypted Data: {}", if context.decrypted_data_is_text { format!("{:?}", context.decrypted_data.iter().map(|&code| char::from_u32(code).unwrap()).collect::<String>()) } else { format!("{:?}", context.decrypted_data) });

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

fn encrypt(context: &mut Context) {
    match input("What data to encrypt?\r\nNumber(s) / Text / File / Already stored data [n/t/f/s]?> ").unwrap().to_lowercase().trim() {
        "n" => {
            let text_ = input("> ").unwrap();
            let numbers_text = text_.trim();
            let mut data: Vec<u32> = Vec::new();

            let mut temp = 0u32;
            let mut temp_ = -1i64;

            for c in numbers_text.chars().rev() {
                match c {
                    '0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9' => {
                        temp_ += 1;
                        temp += ((c as u8 - b'0') as u32) * 10u32.pow(temp_.try_into().unwrap());
                    },
                    ' ' => {
                        if temp_ >= 0 {
                            data.push(temp);
                            temp = 0;
                            temp_ = -1; 
                        }
                    },
                    _ => {
                        println!("Please input one or more numbers seperated by spaces");
                        return;
                    }
                }
            }

            if temp_ >= 0 {
                data.push(temp);
            }

            data.reverse();
            context.data = data;
            context.data_is_text = false;
        },
        "t" => {
            let text_ = input("> ").unwrap();
            context.data = text_.trim().chars().map(|c| c as u32).collect::<Vec<u32>>();
            context.data_is_text = true;
        }
        "s" => {},
        "" => return,
        _ => {
            println!("Unknown action");
            return;
        }
    }

    context.encrypted_data = encrypt_data(&context.data, &context.e, &context.n);
    println!("{:?}", context.encrypted_data);
}

fn decrypt(context: &mut Context) {
    context.decrypted_data = decrypt_data(&context.encrypted_data, &context.d, &context.n);
    context.decrypted_data_is_text = context.data_is_text;

    println!("{}", if context.decrypted_data_is_text { format!("{:?}", context.decrypted_data.iter().map(|&code| char::from_u32(code).unwrap()).collect::<String>()) } else { format!("{:?}", context.decrypted_data) });
}

fn main() {
    help(false);

    let mut context = Context {
        keys: false,
        c: false,
        data_is_text: false,
        decrypted_data_is_text: false,
        p: BigUint::zero(),
        q: BigUint::zero(),
        n: BigUint::zero(),
        phi_n: BigUint::zero(),
        e: BigUint::zero(),
        d: BigUint::zero(),
        data: Vec::new(),
        encrypted_data: Vec::new(),
        decrypted_data: Vec::new()
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
                match input("Input Keys or Initial numbers [i/k]?> ").unwrap().to_lowercase().trim() {
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
                                return;
                            }
                        }
                        match BigUint::from_str(&input("q > ").unwrap()) {
                            Ok(q_) => context.q = q_,
                            Err(_) => {
                                println!("Not a number");
                                return;
                            }
                        }

                        context.c = true;
                        generate_keys(&mut context, 0u32, false);
                        context.keys = true;
                    }
                    _ => println!("Unknown action")
                }
            },
            "e" => {
                if context.keys {
                    encrypt(&mut context)
                } else {
                    println!("Generate or input keys first");
                }
            },
            "d" => decrypt(&mut context),
            "s" =>  show(&context),
            "h" => help(true),
            "q" => return,
            "" => {},
            _ => println!("Unknown action!")
        }
    }
}
