
use sha3::{Digest, Sha3_256};
use rayon::prelude::*;
use std::fs::OpenOptions;
use std::io::{Write, Read};
use std::mem;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use crate::password::Password;
use crate::reduction::reduction;


const CHAIN_LENGTH_MIN : u16 = 1;
const CHAIN_LENGTH_MAX : u16 = 2048;

pub fn generation_main(path: Option<std::path::PathBuf>, use_mem: bool, chain_length: u16) {
    let path = path.unwrap().to_str().unwrap().to_string();
    let thread = num_cpus::get() as u64;

    if chain_length < CHAIN_LENGTH_MIN || chain_length > CHAIN_LENGTH_MAX {
        panic!("Chain length must be between {} and {}", CHAIN_LENGTH_MIN, CHAIN_LENGTH_MAX);
    }

    // Propertly stop the program
    let stop_me: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let stop_me_ctrlc = stop_me.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C received! Exiting...");
        stop_me_ctrlc.store(true, std::sync::atomic::Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // number of passwords to generate per thread
    let slice = 64_u64.pow(7) / thread;    

    let mut passwords: Vec<Password> = Vec::new();
    // check if memory file exists
    if use_mem && std::path::Path::new(&(path.clone() + "mem.txt")).exists() {
        let mut file = std::fs::File::open(path.clone() + "mem.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut passwords_str = contents.split("\n").collect::<Vec<&str>>();
        passwords_str.pop();
        passwords_str.par_sort();
        passwords = passwords_str.into_par_iter().map(|p| Password { password: p.to_string() }).collect();
    } else {
        for i in 0..thread {
            passwords.push(Password { password: "0000000".to_string() } + slice * i);
        }
    }

    let mem_file = Mutex::new(
        OpenOptions::new()
        .create(true)
        .write(true)
        .open(path.clone() + "mem.txt")
        .unwrap()
    );
    
    (0..thread).into_par_iter().for_each(|i: u64| {
        let password = generation(&stop_me, slice, i, passwords[i as usize].clone(), chain_length, path.clone());
        mem_file.lock().unwrap().write_all(format!("{}\n", password.password).as_bytes()).unwrap();
    });

    // Close the memory file
    mem_file.lock().unwrap().sync_all().unwrap();
    mem_file.lock().unwrap().flush().unwrap();
    mem::drop(mem_file);
}

fn generation(stop_me: &Arc<AtomicBool>, slice: u64, i: u64, start: Password, chain_length: u16, path: String) -> Password {
    // Open a file in in append mode
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path + format!("test_{}.txt", i).as_str())
        .unwrap();

    // Contruct a hasher
    let mut hasher = Sha3_256::new();

    // Create the first and last password
    let mut password = start;
    let last_password = Password { password: "0000000".to_string() } + (slice * (i + 1) - 1);

    // Generate the passwords while the stop_me flag is not set and the password is less than the last password
    while !stop_me.load(std::sync::atomic::Ordering::Relaxed) && password < last_password {
        let mut password_tmp = password.password.clone();

        // Generate the chain
        for offset in 0..chain_length {
            hasher.update(password_tmp.clone());
            let hash = hasher.finalize_reset().to_vec();
            password_tmp = reduction(&hash, offset);
        }

        // Write the first and last password to the file
        let buf = format!("{}{}\n", password.password, password_tmp);
        file.write_all(buf.as_bytes()).unwrap();
        password = password + 100;
    }

    // Close the file
    file.sync_all().unwrap();
    file.flush().unwrap();
    mem::drop(file);

    // Return the last password
    password
}