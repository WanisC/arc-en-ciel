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
use crate::sha3::hash_password;
use std::time::Instant;

pub fn search_main(path: PathBuf, chain_length: u16, hash: Option<String>, hashs_path: Option<PathBuf>, password_length: usize) {
    println!("get hash");
    let hashs = get_hashs(hash, hashs_path);
    println!("generation reduction");
    let passwords_to_search: Arc<HashMap<Hash, Vec<(String, u16)>>> = Arc::new(generation_reduction(&hashs, chain_length, password_length));
    println!("search chains");
    let start = Instant::now();
    let hash_founded = search_chains(path, passwords_to_search, password_length);
    println!("Time elapsed: {:?}", start.elapsed());

    // print hash not found
    for hash in hashs.iter() {
        if !hash_founded.contains(hash) {
            println!("hash not found: {:?}", hash);
        }
    }
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

fn generation_reduction(hashs: &Vec<Hash>, chain_length: u16, password_length: usize) -> HashMap<Hash, Vec<(String, u16)>> {
    let reduced_passwords: Mutex<HashMap<Hash, Vec<(String, u16)>>> = Mutex::new(HashMap::new());

    hashs.par_iter().for_each(|hash| {
        let mut reducted_passwords_local = Vec::new();
        for length in 1..=chain_length {
            let mut hash_to_red: Vec<u8> = hash.hash.clone();
            let mut password: String;
            for offset in (2..=length).rev() {
                password = reduction(&hash_to_red, chain_length - offset, password_length);
                hash_to_red = hash_password(&password);
            }
            password = reduction(&hash_to_red, chain_length - 1, password_length);
            reducted_passwords_local.push((password.clone(), chain_length - length));
        }
        reduced_passwords.lock().unwrap().insert(hash.clone(), reducted_passwords_local);
    });

    reduced_passwords.into_inner().unwrap()
}


fn search_chains(path: PathBuf, passwords_to_search: Arc<HashMap<Hash, Vec<(String, u16)>>>, password_length: usize) -> Vec<Hash> {
    let thread = num_cpus::get() as u64;
    
    let hash_founded: Mutex<Vec<Hash>> = Mutex::new(Vec::new());
    (0..thread).into_par_iter().for_each(|t| {
        let path = path.clone().to_str().unwrap().to_string();
        let file = OpenOptions::new()
        .read(true)
        .open(path.clone() + format!("test_{}.txt", t).as_str())
        .unwrap();

        let c = (2 * password_length + 1) * 100000;

        let mut buf = vec![0; c];
        let mut offset = 0;
        while file.seek_read(&mut buf, offset).unwrap() != 0 {
            let contents = String::from_utf8(buf.to_vec()).unwrap();
            let mut passwords = contents.split("\n").collect::<Vec<&str>>();
            passwords.pop();
            let passwords: HashMap<String, String> = passwords.into_par_iter().map(|p| (p[password_length..].to_string(), p[0..password_length].to_string())).collect();
            
            if hash_founded.lock().unwrap().len() == passwords_to_search.len() {
                break;
            }
    
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

fn test_reduction(reduc: String, hash: Hash, offset: u32, password_length: usize) -> Option<String> {
    let mut reduc = reduc.clone();
    for i in 0..offset {
        let hash_str: Vec<u8> = sha3_hash(&reduc, Some(256)).hash;
        reduc = reduction(&hash_str, i as u16, password_length);
    }
    if sha3_hash(&reduc, Some(256)) == hash {
        return Some(reduc);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use rand::Rng;
    use crate::password::Password;

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
        let path = PathBuf::from("./output/");
        let password_length = 5;
        let chain_length = 100;
        let hash = None;
        let hashs_path = Some(PathBuf::from("./hashs.txt"));
        search_main(path, chain_length, hash, hashs_path, password_length);
    }
    
    #[test]
    fn test_reduction() {
        // genere n hash de mot de passe de l caractères
        let l = 4;
        let n = 100;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open("hashs.txt")
            .unwrap();

        for _ in 0..n-1 {
            let password = Password::from_b64(vec![0; l].iter().map(|_| rand::thread_rng().gen_range(0..=63) as u64).collect::<Vec<u64>>());
            let hash = sha3_hash(&password.password, Some(256));
            file.write_all(format!("{:?}\n", hash).as_bytes()).unwrap();
            println!("{:?} - {:?}", password.password, hash);
        }
        let password = Password::from_b64(vec![0; l].iter().map(|_| rand::thread_rng().gen_range(0..=63) as u64).collect::<Vec<u64>>());
        let hash = sha3_hash(&password.password, Some(256));
        file.write_all(format!("{:?}", hash).as_bytes()).unwrap();

        file.sync_all().unwrap();
        file.flush().unwrap();
    }
}