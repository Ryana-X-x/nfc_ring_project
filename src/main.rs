use actix_web::{web, App, HttpServer, Responder};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use rand::Rng;

#[derive(Deserialize)]
struct StoreData {
    id: String,
    data: String,
    key: String,
}

#[derive(Deserialize)]
struct RetrieveQuery {
    key: String,
}

// Generates a random IV
fn generate_iv(cipher: Cipher) -> Vec<u8> {
    let iv_len = cipher.iv_len().unwrap();
    let mut iv = vec![0; iv_len];
    rand::thread_rng().fill(&mut iv[..]);
    iv
}

// Encrypt function with proper IV handling and debugging
fn encrypt(data: &str, key: &str) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let iv = generate_iv(cipher);
    println!("IV: {:?}", iv); // Debugging IV output

    // Ensure the key is exactly 32 bytes
    let mut key_bytes = key.as_bytes().to_vec();
    key_bytes.resize(32, 0); // Pad with zeros if shorter, truncate if longer

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key_bytes, Some(&iv)).ok()?;
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    
    let count = match crypter.update(data.as_bytes(), &mut encrypted) {
        Ok(cnt) => cnt,
        Err(e) => {
            println!("Encryption update error: {:?}", e);
            return None;
        }
    };
    
    let rest = match crypter.finalize(&mut encrypted[count..]) {
        Ok(r) => r,
        Err(e) => {
            println!("Encryption finalize error: {:?}", e);
            return None;
        }
    };
    
    encrypted.truncate(count + rest);

    // Store IV alongside encrypted data
    let mut result = iv;
    result.extend_from_slice(&encrypted);
    Some(result)
}


// Decrypt function with IV handling
fn decrypt(data: &[u8], key: &str) -> Option<String> {
    let cipher = Cipher::aes_256_cbc();
    let iv_len = cipher.iv_len().unwrap();

    if data.len() < iv_len {
        return None; // Invalid data length
    }

    let (iv, encrypted_data) = data.split_at(iv_len);
    
    // Ensure the key is exactly 32 bytes
    let mut key_bytes = key.as_bytes().to_vec();
    key_bytes.resize(32, 0);

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key_bytes, Some(iv)).ok()?;
    let mut decrypted = vec![0; encrypted_data.len() + cipher.block_size()];
    
    let count = match crypter.update(encrypted_data, &mut decrypted) {
        Ok(cnt) => cnt,
        Err(e) => {
            println!("Decryption update error: {:?}", e);
            return None;
        }
    };
    
    let rest = match crypter.finalize(&mut decrypted[count..]) {
        Ok(r) => r,
        Err(e) => {
            println!("Decryption finalize error: {:?}", e);
            return None;
        }
    };
    
    decrypted.truncate(count + rest);
    String::from_utf8(decrypted).ok()
}


// Shared state for storing encrypted data
struct AppState {
    medical_data: Mutex<HashMap<String, Vec<u8>>>,
}

async fn store_data(data: web::Json<StoreData>, state: web::Data<AppState>) -> impl Responder {
    let encrypted_data = match encrypt(&data.data, &data.key) {
        Some(enc) => enc,
        None => return "Encryption failed".to_string(),
    };

    let mut medical_data = state.medical_data.lock().unwrap();
    medical_data.insert(data.id.clone(), encrypted_data);
    format!("Data stored securely for ID: {}", data.id)
}

async fn retrieve_data(id: web::Path<String>, query: web::Query<RetrieveQuery>, state: web::Data<AppState>) -> impl Responder {
    let medical_data = state.medical_data.lock().unwrap();
    if let Some(encrypted_data) = medical_data.get(&id.into_inner()) {
        match decrypt(encrypted_data, &query.into_inner().key) {
            Some(decrypted_data) => format!("Retrieved data: {}", decrypted_data),
            None => "Decryption failed".to_string(),
        }
    } else {
        "Data not found".to_string()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let data = web::Data::new(AppState {
        medical_data: Mutex::new(HashMap::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/store", web::post().to(store_data))
            .route("/retrieve/{id}", web::get().to(retrieve_data))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
