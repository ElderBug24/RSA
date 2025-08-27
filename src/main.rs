use std::fmt;
use std::io;
use std::io::{Write, Read};
use std::fs;
use std::str::FromStr;
use std::time::Instant;

use rand::Rng;
use num_bigint::{BigUint, RandBigInt, BigInt, ToBigInt};
use num_traits::{One, Zero, ToPrimitive, ToBytes};
use num_integer::Integer;
use num_primes;


const SECURITY: u32 = 4;


struct Context {
    p: Option<BigUint>,
    q: Option<BigUint>,
    n: Option<BigUint>,
    phi_n: Option<BigUint>,
    e: Option<BigUint>,
    d: Option<BigUint>,
    data: DataList,
    encrypted_data: EncryptedDataList,
    decrypted_data: DataList
}

enum DataList {
    Numbers(Vec<BigUint>),
    Text(Vec<u32>),
    Empty
}

enum EncryptedDataList {
    EncryptedNumbers(Vec<BigUint>),
    EncryptedText(Vec<BigUint>),
    Empty
}

impl fmt::Display for DataList {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DataList::Numbers(data) => write!(formatter, "{:?}", data),
            DataList::Text(data) => write!(formatter, "\"{}\"", data.iter().map(|&code| char::from_u32(code).unwrap()).collect::<String>()),
            DataList::Empty => write!(formatter, "[]")
        }
    }
}

impl fmt::Display for EncryptedDataList {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncryptedDataList::EncryptedNumbers(data) => write!(formatter, "{:?}", data),
            EncryptedDataList::EncryptedText(data) => write!(formatter, "{:?}", data),
            EncryptedDataList::Empty => write!(formatter, "[]")
        }
    }
}

fn input(prompt: &str) -> Result<String, &str> {
    let mut s = String::new();
    print!("{prompt}");
    let _ = io::stdout().flush();
    match io::stdin().read_line(&mut s) {
        Ok(_) => {
            if let Some('\n') = s.chars().next_back() { s.pop(); }
            if let Some('\r') = s.chars().next_back() { s.pop(); }
            return Ok(s)
    },
        Err(_) => return Err("Error: Failed to read line")
    }
}

fn parse_integer<T: FromStr>(text: &str) -> Result<T, ()> {
    let mut text_ = String::new();

    for c in text.chars() {
        match c {
            n@('0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9') => text_.push(n),
            '_'|'.'|','|' '|'\n' => {},
            _ => return Err(())
        }
    }

    match T::from_str(&text_) {
        Ok(num) => Ok(num),
        Err(_) => Err(())
    }
}

fn parse_integers<T: FromStr>(mut text: String) -> Result<Vec<T>, ()> {
    if let Some('[') = text.chars().next() { text.remove(0); }
    if let Some(']') = text.chars().next_back() { text.pop(); }

    let mut data: Vec<T> = Vec::new();

    let mut i = 0usize;
    let mut s = 0usize;

    for c in text.chars() {
        match c {
            '0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9'|'_'|'.' => {},
            ' '|','|'\n' => {
                if s < i {
                    match parse_integer::<T>(&text[s..i]) {
                        Ok(num) => data.push(num),
                        Err(_) => return Err(())
                    }
                }
                s = i + 1;
            },
            _ => return Err(())
        }

        i += 1;
    }

    if s < i {
        match T::from_str(&text[s..i]) {
            Ok(num) => data.push(num),
            Err(_) => return Err(())
        }
    }

    return Ok(data);
}

fn input_integer<T: FromStr>(prompt: &str) -> Result<T, &str> {
    match parse_integer::<T>(&input(prompt).unwrap()) {
        Ok(num) => Ok(num),
        Err(_) => Err("Error: Not a number")
    }
}

fn input_integers<T: FromStr>(prompt: &str) -> Result<Vec<T>, &str> {
    let numbers_text = input(prompt).unwrap();

    match parse_integers::<T>(numbers_text) {
        Ok(data) => Ok(data),
        Err(_) => Err("Error: Please input one or more numbers seperated by spaces and/or commas, brackets are allowed at the start and at the end")
    }
}

fn write_file(filename: &str, data: &[u8]) -> Result<(), &'static str> {
    let mut file = match fs::File::create(filename) {
        Ok(file) => file,
        Err(_) => return Err("Error: Failed to open file")
    };

    match file.write_all(data) {
        Ok(_) => Ok(()),
        Err(_) => Err("Error: Failed to write to file")
    }
}

fn read_file(filename: &str) -> Result<String, &str> {
    let file = match fs::File::open(filename) {
        Ok(file) => file,
        Err(_) => return Err("Error: Failed to open file")
    };

    let mut buf_reader = io::BufReader::new(file);
    let mut contents = String::new();

    match buf_reader.read_to_string(&mut contents) {
        Ok(_) => Ok(contents),
        Err(_) => Err("Error: Failed to read file")
    }
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
        return None;
    }

    while xy.0 < BigInt::zero() {
        xy.0 += &m;
    }

    return Some(xy.0.to_biguint().unwrap());
}

fn test_keys(e: &BigUint, d: &BigUint, n: &BigUint) -> bool {
    let mut rng = rand::thread_rng();
    let mut failed = false;

    let mut random: Box<dyn FnMut() -> u32> = if n <= &BigUint::from(u32::MAX) {
        Box::new(move || rng.gen_biguint_below(n).to_u32().unwrap())
    } else {
        Box::new(move || rng.gen_range(2..u32::MAX))
    };

    for _ in 0..SECURITY {
        let (num1, num2) = (random(), random());
        let numv = vec![num1, num2];
        let e_numv = encrypt_bytes(&numv, e, n);
        let d_nums = decrypt_bytes(&e_numv, d, n);

        failed |= num1 != d_nums[0] || num2 != d_nums[1];

        if failed {
            return true;
        }
    }

    return false;
}

fn generate_keys(context: &mut Context, size: u32) {
    let start = Instant::now();

    let mut rng = rand::thread_rng();

    let p: BigUint;
    let q: BigUint;

    print!("|      | Generating p...");
    let _ = io::stdout().flush();
    if context.p.is_none()  {
        p = BigUint::from_bytes_be(&num_primes::Generator::new_prime(size as usize).to_bytes_be());
    } else {
        p = context.p.clone().unwrap();
    }

    print!("\r|#     | Generating q...");
    let _ = io::stdout().flush();
    if context.q.is_none() {
        q = BigUint::from_bytes_be(&num_primes::Generator::new_prime(size as usize).to_bytes_be());
    } else {
        q = context.q.clone().unwrap();
    }

    print!("\r|##    | Calculating N...");
    let _ = io::stdout().flush();
    let n = &p * &q;
    print!("\r|###   | Calculating Phi(N)...");
    let _ = io::stdout().flush();
    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());
    print!("\r|####  | Generating e...      ");
    let _ = io::stdout().flush();

    let e = BigUint::from( if &phi_n > &BigUint::from(65537u32) {
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
    print!("\r|##### | Calculating d...");
    let _ = io::stdout().flush();

    let mut d = modinv(&e, &phi_n).unwrap();
    if d == e {
        d += &phi_n;
    }

    context.p = Some(p);
    context.q = Some(q);
    context.n = Some(n);
    context.phi_n = Some(phi_n);
    context.e = Some(e);
    context.d = Some(d);

    print!("\r|######| Testing keys... ");
    let _ = io::stdout().flush();
    let _ = io::stdout().flush();
    if test_keys(context.e.as_ref().unwrap(), &context.d.as_ref().unwrap(), &context.n.as_ref().unwrap()) {
        panic!("Failed!");
    }

    println!("\rDone in {:.3?}          ", start.elapsed());
}

fn show(context: &Context) {
    if let Some(num) = &context.p { println!("p: {num}"); }
    if let Some(num) = &context.q { println!("q: {num}"); }
    if let Some(num) = &context.n { println!("N: {num}"); }
    if let Some(num) = &context.phi_n { println!("Phi(N): {num}"); }
    if let Some(num) = &context.e { println!("e: {num}"); }
    if let Some(num) = &context.d { println!("d: {num}"); }

    println!("Data: {}", context.data);
    println!("Encrypted Data: {}", context.encrypted_data);
    println!("Decrypted Data: {}", context.decrypted_data);

}

fn encrypt_byte(data: u8, e: &BigUint, n: &BigUint) -> BigUint {
    let b = BigUint::from(data);
    return b.modpow(&e, &n);
}

fn decrypt_byte(data: &BigUint, d: &BigUint, n: &BigUint) -> u8 {
    let b: u8 = data.modpow(&d, &n).to_u8().unwrap();
    return b;
}

fn encrypt_bytes(data: &Vec<u32>, e: &BigUint, n: &BigUint) -> Vec<BigUint> {
    let mut encrypted_data: Vec<BigUint> = Vec::with_capacity(data.len() * 4);

    for num in data {
        let num = num.to_be_bytes();
        for b in num {
            encrypted_data.push(encrypt_byte(b, &e, &n));
        }
    }

    return encrypted_data;
}

fn decrypt_bytes(encrypted_data: &Vec<BigUint>, d: &BigUint, n: &BigUint) -> Vec<u32> {
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

fn encrypt_data(data: &DataList, e: &BigUint, n: &BigUint) -> EncryptedDataList {
    match data {
        DataList::Numbers(data) => {
            let mut encrypted_data: Vec<BigUint> = Vec::with_capacity(data.len());

            for num in data {
                encrypted_data.push(num.modpow(&e, &n));
            }

            return EncryptedDataList::EncryptedNumbers(encrypted_data);
        },
        DataList::Text(data) => return EncryptedDataList::EncryptedText(encrypt_bytes(&data, &e, &n)),
        DataList::Empty => return EncryptedDataList::Empty
    }
}

fn decrypt_data(encrypted_data: &EncryptedDataList, d: &BigUint, n: &BigUint) -> DataList {
    match encrypted_data {
        EncryptedDataList::EncryptedNumbers(encrypted_data) => {
            let mut data: Vec<BigUint> = Vec::with_capacity(encrypted_data.len());

            for num in encrypted_data {
                data.push(num.modpow(&d, &n));
            }

            return DataList::Numbers(data);
        },
        EncryptedDataList::EncryptedText(data) => return DataList::Text(decrypt_bytes(&data, &d, &n)),
        EncryptedDataList::Empty => return DataList::Empty
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
        println!("f: Import or Export data");
        println!("h: Show this help");
        println!("q: Quit");
    } else {
        println!();
        println!("Type 'h' for help");
    }
}

fn main() {
    help(false);

    let mut context = Context {
        data: DataList::Empty,
        encrypted_data: EncryptedDataList::Empty,
        decrypted_data: DataList::Empty,
        p: None,
        q: None,
        n: None,
        phi_n: None,
        e: None,
        d: None
    };

    loop {
        match input("\r\n[g/i/e/d/s/f/h/q]?> ").unwrap().to_lowercase().trim() {
            "g" => {
                match input_integer::<u32>("Enter key size (2^n) > ") {
                    Ok(size) => {
                        context.p = None;
                        context.q = None;
                        generate_keys(&mut context, size);

                        show(&context);
                    },
                    Err(_) => println!("Error: Not a number")
                }
            },
            "i" => {
                match input("Input Keys or Initial numbers [i/k]?> ").unwrap().to_lowercase().trim() {
                    "i" => {                        
                        match input_integer::<BigUint>("p > ") {
                            Ok(p_) => context.p = Some(p_),
                            Err(e) => {
                                println!("{e}");
                                continue;
                            }
                        }
                        match input_integer::<BigUint>("q > ") {
                            Ok(q_) => context.q = Some(q_),
                            Err(e) => {
                                println!("{e}");
                                continue;
                            }
                        }

                        generate_keys(&mut context, 0u32);
                    },
                    "k" => {
                        match input("e > ").unwrap().trim() {
                            "" => {},
                            text => {
                                match BigUint::from_str(text) {
                                    Ok(e) => context.e = Some(e),
                                    Err(_) => println!("Error: Not a number")
                                }
                            }
                        }
                        match input("d > ").unwrap().trim() {
                            "" => {},
                            text => {
                                match BigUint::from_str(text) {
                                    Ok(d) => context.d = Some(d),
                                    Err(_) => println!("Error: Not a number")
                                }
                            }
                        }
                        match input("N > ").unwrap().trim() {
                            "" => {},
                            text => {
                                match BigUint::from_str(text) {
                                    Ok(n) => context.n = Some(n),
                                    Err(_) => println!("Error: Not a number")
                                }
                            }
                        }
                    },
                    _ => println!("Error: Unknown action")
                }
            },
            "e" => {
                if context.e.is_none() || context.n.is_none() {
                    println!("Error: Generate or input keys first");
                } else {
                    match input("What data to encrypt?\r\nNumber(s) / Text / File / Already stored data [n/t/f/s]?> ").unwrap().to_lowercase().trim() {
                        "n" => {
                            match input_integers::<BigUint>("> ") {
                                Ok(data) => context.data = DataList::Numbers(data),
                                Err(e) => {
                                    println!("{e}");
                                    continue;
                                }
                            }
                        },
                        "t" => {
                            let text = input("> ").unwrap();
                            context.data = DataList::Text(text.trim().chars().map(|c| c as u32).collect::<Vec<u32>>());
                        },
                        "f" => {
                            let data = match read_file(&input("Filename > ").unwrap()) {
                                Ok(contents) => contents,
                                Err(e) => {
                                    println!("{e}");
                                    continue;
                                }
                            };

                            context.data = match input("Interprete this data as Number(s) or Text [n/t]?> ").unwrap().to_lowercase().trim() {
                                "n" => {
                                    match parse_integers::<BigUint>(data) {
                                        Ok(data) => DataList::Numbers(data),
                                        Err(_) => {
                                            println!("Error: Couldn't parse data");
                                            continue;
                                        }
                                    }
                                },
                                "t" => DataList::Text(data.trim().chars().map(|c| c as u32).collect::<Vec<u32>>()),
                                _ => {
                                    println!("Error: Unknown action");
                                    continue;
                                }
                            };
                        },
                        "s" => {},
                        "" => continue,
                        _ => {
                            println!("Error: Unknown action");
                            continue;
                        }
                    }

                    context.encrypted_data = encrypt_data(&context.data, context.e.as_ref().unwrap(), context.n.as_ref().unwrap());
                    println!("{}", context.encrypted_data);
                }
            },
            "d" => {
                if context.d.is_none() || context.n.is_none() {
                    println!("Error: Generate or input keys first");
                } else {
                    match input("What data to decrypt?\r\nNumber(s) / Text / File / Already stored encrypted data [n/t/f/s]?> ").unwrap().to_lowercase().trim() {
                        "n" => match input_integers::<BigUint>("> ") {
                            Ok(data) => {
                                context.encrypted_data = EncryptedDataList::EncryptedNumbers(data);
                            },
                            Err(e) => {
                                println!("{e}");
                                continue;
                            }
                        },
                        "t" => match input_integers::<BigUint>("> ") {
                            Ok(data) => {
                                context.encrypted_data = EncryptedDataList::EncryptedText(data);
                            },
                            Err(e) => {
                                println!("{e}");
                                continue;
                            }
                        },
                        "f" => {
                            let data = match read_file(&input("Filename > ").unwrap()) {
                                Ok(contents) => contents,
                                Err(e) => {
                                    println!("{e}");
                                    continue;
                                }
                            };

                            context.encrypted_data = match input("Interprete this data as Encrypted Number(s) or Encrypted Text [n/t]?> ").unwrap().to_lowercase().trim() {
                                "n" => {
                                    match parse_integers::<BigUint>(data) {
                                        Ok(data) => EncryptedDataList::EncryptedNumbers(data),
                                        Err(_) => {
                                            println!("Error: Couldn't parse data");
                                            continue;
                                        }
                                    }
                                },
                                "t" => {
                                    match parse_integers::<BigUint>(data) {
                                        Ok(data) => EncryptedDataList::EncryptedText(data),
                                        Err(_) => {
                                            println!("Error: Couldn't parse data");
                                            continue;
                                        }
                                    }
                                },
                                _ => {
                                    println!("Error: Unknown action");
                                    continue;
                                }
                            };
                        },

                        "s" => {
                            if let EncryptedDataList::Empty = context.encrypted_data {
                                println!("Error: Encrypt Data first");
                                continue;
                            }
                        },
                        "" => continue,
                        _ => {
                            println!("Error: Unknown action");
                            continue;
                        }
                    }

                    context.decrypted_data = decrypt_data(&context.encrypted_data, context.d.as_ref().unwrap(), context.n.as_ref().unwrap());
                    println!("{}", context.decrypted_data);
                }
            }
            "s" =>  show(&context),
            "f" => {
                match input("Do you want to Import or Export data [i/e]?> ").unwrap().to_lowercase().trim() {
                    "i" => {
                        let data = match read_file(&input("Filename > ").unwrap()) {
                            Ok(data) => data,
                            Err(e) => {
                                println!("{e}");
                                continue;
                            }
                        };

                        match (|| -> Result<(), &str> {
                            match input("What data is contained in the file [p/q/n/phi_n/e/d/data/edata]?> ").unwrap().to_lowercase().trim() {
                                num@("p"|"q"|"n"|"phi_n"|"e"|"d") => {
                                    match parse_integer::<BigUint>(&data) {
                                        Ok(n) => {
                                            match num {
                                                "p" => context.p = Some(n),
                                                "q" => context.q = Some(n),
                                                "n" => context.n = Some(n),
                                                "phi_n" => context.phi_n = Some(n),
                                                "e" => context.e = Some(n),
                                                "d" => context.d = Some(n),
                                                _ => return Err("")
                                            }
                                        },
                                        Err(_) => return Err("Error: Couldn't parse data")
                                    }
                                },
                                list@("data"|"edata") => {
                                    match list {
                                        "data" => {
                                            match input("Interprete this data as Number(s) or Text [n/t]?> ").unwrap().to_lowercase().trim() {
                                                "n" => {
                                                    match parse_integers::<BigUint>(data) {
                                                        Ok(l) => context.data = DataList::Numbers(l),
                                                        Err(_) => return Err("Error: Couldn't parse data")
                                                    }
                                                },
                                                "t" => context.data = DataList::Text(data.trim().chars().map(|c| c as u32).collect::<Vec<u32>>()),
                                                _ => return Err("Error: Unknown action")
                                            }
                                        },
                                        "edata" => {
                                            match input("Interprete this data as Encrypted Number(s) or Encrypted Text [n/t]?> ").unwrap().to_lowercase().trim() {
                                                "n" => {
                                                    match parse_integers::<BigUint>(data) {
                                                        Ok(l) => context.encrypted_data = EncryptedDataList::EncryptedNumbers(l),
                                                        Err(_) => return Err("Error: Couldn't parse data")
                                                    }
                                                },
                                                "t" => {
                                                    match parse_integers::<BigUint>(data) {
                                                        Ok(l) => context.encrypted_data = EncryptedDataList::EncryptedText(l),
                                                        Err(_) => return Err("Error: Couldn't parse data")
                                                    }
                                                }
                                                _ => return Err("Error: Unknown action")
                                            }
                                        },
                                        _ => return Err("")
                                    }
                                },
                                _ => return Err("Error: Unknown action")
                            }
                            Ok(())
                        })() {
                            Ok(_) => {},
                            Err(e) => println!("{e}")
                        }
                    },
                    "e" => {
                        let data: String = match (|| -> Result<String, &str> {
                            return Ok( match input("What do you want to export?\r\n[p/q/n/phi_n/e/d/data/edata/ddata]?> ").unwrap().to_lowercase().trim() {
                                num@("p"|"q"|"n"|"phi_n"|"e"|"d") => {
                                    let n: &BigUint = match num {
                                        "p" => if let Some(ref p) = context.p { p } else { return Err("Not set yet"); }
                                        "q" => if let Some(ref q) = context.q { q } else { return Err("Not set yet"); }
                                        "n" => if let Some(ref n) = context.n { n } else { return Err("Not set yet"); }
                                        "phi_n" => if let Some(ref phi_n) = context.phi_n { phi_n } else { return Err("Not set yet"); }
                                        "e" => if let Some(ref e) = context.e { e } else { return Err("Not set yet"); }
                                        "d" => if let Some(ref d) = context.d { d } else { return Err("Not set yet"); }
                                        _ => return Err("")
                                    };

                                    format!("{n}\n")
                                },
                                list@("data"|"edata"|"ddata") => {
                                    let mut s = String::new();
                                    match list {
                                        l@("data"|"ddata") => {
                                            match match l {
                                                "data" => &context.data,
                                                "ddata" => &context.decrypted_data,
                                                _ => return Err("")
                                            } {
                                                DataList::Numbers(l) => for num in l { s.push_str(&format!("{num}\n")); },
                                                DataList::Text(l) => for num in l { s.push_str(&format!("{num}\n")); },
                                                DataList::Empty => {}
                                            }
                                        },
                                        "edata" => match &context.encrypted_data {
                                            EncryptedDataList::EncryptedNumbers(l)|EncryptedDataList::EncryptedText(l) => for num in l { s.push_str(&format!("{num}\n")); },
                                            EncryptedDataList::Empty => {}
                                        },
                                        _ => return Err("")
                                    };

                                    s
                                },
                                _ => return Err("Error: Unknown action")
                            } );
                        })() {
                            Ok(data) => data,
                            Err(e) => {
                                println!("{e}");
                                continue;
                            }
                        };

                        match write_file(&input("Filename > ").unwrap(), &data.into_bytes()) {
                            Ok(_) => {},
                            Err(e) => println!("{e}")
                        }
                    }
                    _ => println!("Error: Unknown action")
                }
            },
            "h" => help(true),
            "q" => return,
            "" => {},
            _ => println!("Error: Unknown action")
        }
    }
}

