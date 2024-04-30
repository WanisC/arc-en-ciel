//! Implementation of the different search functions used to retrieve the password from the hash

use std::io::Read;
use std::os::windows::fs::FileExt;
use std::path::PathBuf;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fs::OpenOptions;
use crate::hashage::sha3_hash;
use crate::reduction::reduction;
use crate::hash::Hash;
use std::time::Instant;

/// Search the password from the hash.
/// # Arguments
/// * `path` - The path to the file containing the passwords
/// * `chain_length` - The length of the chain
/// * `hash` - The hash to search
/// * `hashs_path` - The path to the file containing the hashs
/// * `password_length` - The length of the password
pub fn search_main(path: PathBuf, _use_mem: bool, chain_length: u16, hash: Option<String>, hashs_path: Option<PathBuf>, password_length: usize) {
    println!("Get hash");
    let hashs = get_hashs(hash, hashs_path);
    println!("Generation reduction");
    let passwords_to_search = Arc::new(generation_reduction(&hashs, chain_length, password_length));
    println!("Search chains");
    let start = Instant::now();
    let hash_founded = search_chains(path, passwords_to_search, password_length);
    println!("Time elapsed: {:?}", start.elapsed());

    // For each hash, check if it has been found
    for hash in hashs.iter() {
        // If the hash has not been found, print an message to the user
        if !hash_founded.contains(hash) {
            println!("Hash not found: {:?}", hash);
        }
    }
}

/// Get the hashs from the hash or the hashs file.
/// # Arguments
/// * `hash` - The hash to search
/// * `hashs_path` - The path to the file containing the hashs
/// # Returns
/// A vector containing the hashs.
fn get_hashs(hash: Option<String>, hashs_path: Option<PathBuf>) -> Vec<Hash> {
    let mut hashs = Vec::new(); // Vector containing the hashs
    // If the hash is not None, add it to the vector
    if let Some(hash) = hash {
        hashs.push(Hash::from(hash));
    }
    // If the hashs_path is not None, add the hashs from the file to the vector
    else if let Some(hashs_path) = hashs_path {
        // Open the file in read-only mode
        let mut file = OpenOptions::new()
            .read(true)
            .open(hashs_path.clone())
            .unwrap();

        // Read the file contents into a string
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        
        hashs = buf.split("\n").collect::<Vec<&str>>().iter().map(|hash| {
            Hash::from(hash.to_string())
        }).collect::<Vec<Hash>>();
    }
    hashs
}

/// Generate the reduced passwords from the hashs.
/// # Arguments
/// * `hashs` - The hashs to generate the reduced passwords
/// * `chain_length` - The length of the chain
/// * `password_length` - The length of the password
/// # Returns
/// A hashmap containing the hashs and the reduced passwords.
fn generation_reduction(hashs: &Vec<Hash>, chain_length: u16, password_length: usize) -> HashMap<Hash, Vec<(String, u16)>> {
    // Initialize a hashmap containing the hashs and the reduced passwords
    let reduced_passwords: Mutex<HashMap<Hash, Vec<(String, u16)>>> = Mutex::new(HashMap::new());

    // For each hash, generate the reduced passwords
    hashs.par_iter().for_each(|hash| {
        let mut reducted_passwords_local = Vec::new();
        // 1 <= length <= chain_length
        for length in 1..=chain_length {
            let mut hash_to_red: Vec<u8> = hash.hash.clone();
            let mut password: String;
            for offset in (2..=length).rev() {
                password = reduction(&hash_to_red, chain_length - offset, password_length);
                hash_to_red = sha3_hash(&password, Some(256)).hash;
            }
            // Generate the reduced password
            password = reduction(&hash_to_red, chain_length - 1, password_length);
            // Add the reduced password to the hashmap
            reducted_passwords_local.push((password.clone(), chain_length - length));
        }
        // Add the reduced passwords to the hashmap
        reduced_passwords.lock().unwrap().insert(hash.clone(), reducted_passwords_local);
    });

    reduced_passwords.into_inner().unwrap()
}

/// Search the chains to retrieve the password from the hash.
/// # Arguments
/// * `path` - The path to the file containing the passwords
/// * `passwords_to_search` - The passwords to search
/// * `password_length` - The length of the password
/// # Returns
/// A vector containing the hashs found.
fn search_chains(path: PathBuf, passwords_to_search: Arc<HashMap<Hash, Vec<(String, u16)>>>, password_length: usize) -> Vec<Hash> {
    // Get the number of available CPUs of the current system   
    let thread = num_cpus::get() as u64;
    
    // Initialize a vector containing the hashs found
    let hash_founded: Mutex<Vec<Hash>> = Mutex::new(Vec::new());

    // For each thread, search the chains
    (0..thread).into_par_iter().for_each(|t| {
        let path = path.clone().to_str().unwrap().to_string();
        let file = OpenOptions::new()
        .read(true)
        .open(path.clone() + format!("test_{}.txt", t).as_str())
        .unwrap();

        let c = (2 * password_length + 1) * 100000;

        let mut buf = vec![0; c];
        let mut offset = 0;
        // Read the file and search the password
        while file.seek_read(&mut buf, offset).unwrap() != 0 {
            let contents = String::from_utf8(buf.to_vec()).unwrap();
            let mut passwords = contents.split("\n").collect::<Vec<&str>>();
            passwords.pop();
            let passwords: HashMap<String, String> = passwords.into_par_iter().map(|p| (p[password_length..].to_string(), p[0..password_length].to_string())).collect();
            
            if hash_founded.lock().unwrap().len() == passwords_to_search.len() {
                break;
            }
    
            // For each hash, search the password
            passwords_to_search.iter().for_each(|(hash, password_list)| {
                for (password, offset) in password_list.iter().rev() {
                    if hash_founded.lock().unwrap().contains(hash) {
                        break;
                    }
                    if passwords.contains_key(password) { 
                        if let Some(reduc) = test_reduction(passwords.get(password).unwrap().clone(), hash.clone(), *offset as u32, password_length) {
                            if !hash_founded.lock().unwrap().contains(hash) {
                                hash_founded.lock().unwrap().push(hash.clone());
                                println!("hash found: {:?} password: {}", hash, reduc);
                            }
                            break;
                        }
                    }
                }
            });
            offset += c as u64;
        }


    });
    hash_founded.into_inner().unwrap()
}

/// Test the reduction function.
/// # Arguments
/// * `reduc` - The password to reduce
/// * `hash` - The hash to compare
/// * `offset` - The offset to reduce
/// * `password_length` - The length of the password
/// # Returns
/// The reduced password if the hash is found, None otherwise.
fn test_reduction(reduc: String, hash: Hash, offset: u32, password_length: usize) -> Option<String> {
    let mut reduc = reduc.clone();
    // 0 <= i < offset
    for i in 0..offset {
        // Initialize a vector containing the hash of the reduced password
        let hash_str: Vec<u8> = sha3_hash(&reduc, Some(256)).hash;
        reduc = reduction(&hash_str, i as u16, password_length);
    }
    // If the hash of the reduced password is equal to the hash, return the reduced password
    if sha3_hash(&reduc, Some(256)) == hash {
        return Some(reduc);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_reduction() {
        let hashs = vec![
            Hash::from("bf35db71c337cf0701082699459d12442e5e27ba1cf2fb4eae2cafad41c45d2e".to_string()),
        ];
        let chain_length = 100;
        let password_length = 4;
        println!("{:#?}", generation_reduction(&hashs, chain_length, password_length));
    }

    #[test]
    fn test_search_main() {
        let path = PathBuf::from("G:/");
        let password_length = 4;
        let use_mem = false;
        let chain_length = 100;
        let hash = None;
        let hashs_path = Some(PathBuf::from("./hashs.txt"));
        search_main(path, use_mem, chain_length, hash, hashs_path, password_length);
    }
}