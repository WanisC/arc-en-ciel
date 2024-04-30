
use rayon::prelude::*;
use std::fs::OpenOptions;
use std::io::{Write, Read};
use std::mem;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::path::PathBuf;

use crate::password::Password;
use crate::reduction::reduction;
use crate::hashage::sha3_hash;

const CHAIN_LENGTH_MIN : u16 = 1;
const CHAIN_LENGTH_MAX : u16 = 2048;

pub fn generation_main(path: Option<std::path::PathBuf>, use_mem: bool, chain_length: u16, password_length: usize) {
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

    let mut passwords: Vec<Password> = Vec::new();
    // check if memory file exists
    if use_mem && std::path::Path::new(&(path.clone() + "mem.txt")).exists() {
        // Read the memory file and store the passwords in a vector
        let mut file = OpenOptions::new()
            .read(true)
            .open(path.clone() + "mem.txt")
            .unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut passwords_str = contents.split("\n").collect::<Vec<&str>>();
        passwords_str.pop();
        passwords_str.par_sort();
        passwords = passwords_str.into_par_iter().map(|p| Password { password: p.to_string() }).collect();
    } else {
        // Generate the first password for each thread
        for i in 0..thread {
            passwords.push(Password { password: "0".repeat(password_length).to_string() } + i);
        }
    }

    // Create the memory file
    std::fs::create_dir_all(PathBuf::from(path.clone()).to_str().unwrap()).unwrap();

    let mem_file = Mutex::new(
        OpenOptions::new()
        .create(true)
        .write(true)
        .open(path.clone() + "mem.txt")
        .unwrap()
    );
    
    (0..thread).into_par_iter().for_each(|i: u64| {
        let password = generation(&stop_me, i, passwords[i as usize].clone(), chain_length, path.clone(), password_length);
        mem_file.lock().unwrap().write_all(format!("{}\n", password.password).as_bytes()).unwrap();
    });

    // Close the memory file
    mem_file.lock().unwrap().sync_all().unwrap();
    mem_file.lock().unwrap().flush().unwrap();
    mem::drop(mem_file);
}

fn generation(stop_me: &Arc<AtomicBool>, i: u64, start: Password, chain_length: u16, path: String, password_length: usize ) -> Password {
    // Open a file in in append mode
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path + format!("test_{}.txt", i).as_str())
        .unwrap();

    // Create the first password
    let mut password = start;
    let offset = (chain_length as f32 * 0.9) as u64 ;
    // Generate the passwords while the stop_me flag is not set and the password is not "?"
    while !stop_me.load(std::sync::atomic::Ordering::Relaxed) && password.password != "?" {
        let mut password_tmp = password.password.clone();

        // Generate the chain
        for offset in 0..chain_length {
            let hash = sha3_hash(&password_tmp, Some(256));
            password_tmp = reduction(&hash.hash, offset, password_length);
        }

        // Write the first and last password to the file
        file.write_all(format!("{}{}\n", password.password, password_tmp).as_bytes()).unwrap();
        password = password + offset;
    }

    // Close the file
    file.sync_all().unwrap();
    file.flush().unwrap();
    mem::drop(file);

    // Return the last password
    password
}