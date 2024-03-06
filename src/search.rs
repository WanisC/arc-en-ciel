use std::io::{Read, Write};
use std::path::PathBuf;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fs::OpenOptions;
use crate::reduction::reduction;
use crate::sha3::hash_password;

pub fn search_main(path: Option<PathBuf>, use_mem: bool, chain_length: u16, hash: Option<Vec<u8>>, hashs_path: Option<PathBuf>) {
    let mut passwords_to_search = Vec::new();
    let mut hashs = Vec::new();
    if let Some(hash) = hash {
        hashs.push(hash);
        passwords_to_search = generation_reduction(hashs, chain_length);

    } else if let Some(hashs_path) = hashs_path {
        let mut file = OpenOptions::new()
            .read(true)
            .open(hashs_path.clone())
            .unwrap();

        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();

        let hashs = Mutex::new(Vec::new());
        let hashs_tmp = buf.split("\n").collect::<Vec<&str>>();
        hashs_tmp.into_par_iter().for_each(|hash: &str| {
            let mut hash_str = hash.to_string();
            let mut hash = Vec::new();
            for _ in 0..32 {
                let byte = u8::from_str_radix(&hash_str[0..2], 16).unwrap();
                hash.push(byte);
                hash_str = hash_str[2..].to_string();
            }
            hashs.lock().unwrap().push(hash);
        });
        
        let hashs = hashs.into_inner().unwrap();
        passwords_to_search = generation_reduction(hashs, chain_length);
    }

    let passwords_to_search = Arc::new(passwords_to_search);
    let thread = num_cpus::get() as u64;
    (0..thread).into_par_iter().for_each(|i| {
        let path = path.clone().unwrap().to_str().unwrap().to_string();
        let mut file = OpenOptions::new()
            .read(true)
            .open(path.clone() + format!("test_{}.txt", i).as_str())
            .unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut passwords = contents.split("\n").collect::<Vec<&str>>();
        passwords.pop();
        let passwords: HashMap<String, String> = passwords.into_par_iter().map(|p| (p[7..].to_string(), p[0..7].to_string())).collect();
        let found_passwords = Mutex::new(Vec::new());

        passwords_to_search.par_iter().for_each(|password| {
            if passwords.contains_key(password) {
                println!("Password found {}", password);
                found_passwords.lock().unwrap().push(password.clone());
            }
        });

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(path + format!("found_passwords_{}.txt", i).as_str())
            .unwrap();

        let found_passwords = found_passwords.into_inner().unwrap();
        for password in found_passwords {
            file.write_all(password.as_bytes()).unwrap();
            file.write_all("\n".as_bytes()).unwrap();
        }
    });
}


fn generation_reduction(hashs: Vec<Vec<u8>>, chain_length: u16) -> Vec<String> {
    let reduced_passwords = Mutex::new(Vec::new());

    hashs.into_par_iter().for_each(|hash| {
        let mut reducted_passwords_local = Vec::new();
        for length in 1..=chain_length {
            let mut hash_to_red = hash.clone();
            let mut password = String::new();
            for offset in (1..=length).rev() {
                password = reduction(&hash_to_red, chain_length - offset);
                hash_to_red = hash_password(&password);
            }
            reducted_passwords_local.push(password.clone());
        }
        reduced_passwords.lock().unwrap().append(&mut reducted_passwords_local);
    });

    reduced_passwords.into_inner().unwrap()
}

/// Search for the password in the given file
// fn search(file: PathBuf, passwords_to_search: Arc<Vec<String>>, hashs: Arc<Vec<String>>) -> Option<Vec<String>> {

// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_reduction() {
        let hashs = vec![
            vec![89, 231, 227, 91, 71, 2, 64, 70, 87, 23, 109, 83, 47, 144, 137, 54, 192, 188, 198, 117, 203, 37, 149, 4, 169, 207, 252, 240, 4, 143, 166, 27]
        ];
        let chain_length = 100;
        println!("{:#?}", generation_reduction(hashs, chain_length));
    }

    #[test]
    fn test_search_main() {
        let path = Some(PathBuf::from("./output/"));
        let use_mem = true;
        let chain_length = 100;
        let hash = None;
        let hashs_path = Some(PathBuf::from("./output/hashs.txt"));
        search_main(path, use_mem, chain_length, hash, hashs_path);
    }
}