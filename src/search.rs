use std::io::{Read, Write};
use std::path::PathBuf;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fs::OpenOptions;
use crate::reduction::reduction;
use crate::sha3::hash_password;
use crate::hash::Hash;

pub fn search_main(path: PathBuf, use_mem: bool, chain_length: u16, hash: Option<String>, hashs_path: Option<PathBuf>) {
    let hashs = get_hashs(hash, hashs_path);
    let passwords_to_search = Arc::new(generation_reduction(&hashs, chain_length));
    let chains_info = search_chains(path, passwords_to_search, chain_length);
    search_output(chains_info);
}

fn get_hashs(hash: Option<String>, hashs_path: Option<PathBuf>) -> Vec<Hash> {
    let mut hashs = Vec::new();
    if let Some(hash) = hash {
        hashs.push(Hash::from(hash));
    }
    else if let Some(hashs_path) = hashs_path {
        // Open the file in read-only mode
        let mut file = OpenOptions::new()
            .read(true)
            .open(hashs_path.clone())
            .unwrap();

        // Read the file contents into a string
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        
        // TODO Gestion erreur: chaine detecter comme pas un hash de 64 caractères
        hashs = buf.split("\n").collect::<Vec<&str>>().iter().map(|hash| {
            Hash::from(hash.to_string())
        }).collect::<Vec<Hash>>();
    }
    hashs
}

fn generation_reduction(hashs: &Vec<Hash>, chain_length: u16) -> Vec<String> {
    let reduced_passwords = Mutex::new(vec![vec![]; hashs.len()]);

    hashs.into_par_iter().enumerate().for_each(|(i, hash)| {
        let mut reducted_passwords_local = Vec::new();
        for length in 1..=chain_length {
            let mut hash_to_red = hash.hash.clone();
            let mut password = String::new();
            for offset in (1..=length).rev() {
                password = reduction(&hash_to_red, chain_length - offset);
                hash_to_red = hash_password(&password);
            }
            reducted_passwords_local.push(password.clone());
        }
        reduced_passwords.lock().unwrap()[i] = reducted_passwords_local;
    });

    reduced_passwords.into_inner().unwrap().concat()
}


fn search_chains(path: PathBuf, passwords_to_search: Arc<Vec<String>>, chain_length: u16) -> Vec<(String, u32, u32)> {
    let chain_length = chain_length as u32;
    let thread = num_cpus::get() as u64;
    
    let chains_info = Mutex::new(Vec::new());
    (0..thread).into_par_iter().for_each(|i| {
        let path = path.clone().to_str().unwrap().to_string();
        let mut file = OpenOptions::new()
        .read(true)
        .open(path.clone() + format!("test_{}.txt", i).as_str())
        .unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut passwords = contents.split("\n").collect::<Vec<&str>>();
        passwords.pop();
        let passwords: HashMap<String, String> = passwords.into_par_iter().map(|p| (p[7..].to_string(), p[0..7].to_string())).collect();
        
        let chains_info_local = Mutex::new(Vec::new());
        passwords_to_search.par_iter().enumerate().for_each(|(i, password)| {
            if passwords.contains_key(password) {
                println!("Chains found {}", password);
                chains_info_local.lock().unwrap().push((password.clone(), i as u32 / chain_length, 99 - i as u32 % chain_length));
            }
        });
        chains_info.lock().unwrap().append(&mut chains_info_local.into_inner().unwrap());
    });
    chains_info.into_inner().unwrap()
}

fn search_output(chains_info: Vec<(String, u32, u32)>) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open("output.txt")
        .unwrap();
    for chain in chains_info {
        file.write_all(format!("{} {} {}\n", chain.0, chain.1, chain.2).as_bytes()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_reduction() {
        let hashs = vec![
            Hash::from("59e7e35b4702404657176d532f908936c0bcc675cb259504a9cffcf0048fa61b".to_string()),
        ];
        let chain_length = 100;
        println!("{:#?}", generation_reduction(&hashs, chain_length));
    }

    #[test]
    fn test_search_main() {
        let path = PathBuf::from("./output/");
        let use_mem = true;
        let chain_length = 100;
        let hash = None;
        let hashs_path = Some(PathBuf::from("./output/hashs.txt"));
        search_main(path, use_mem, chain_length, hash, hashs_path);
    }
}