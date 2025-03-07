use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};
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

#[derive(Serialize)]
struct ResponseData {
    message: String,
}

// Generates a random IV
fn generate_iv(cipher: Cipher) -> Vec<u8> {
    let iv_len = cipher.iv_len().unwrap();
    let mut iv = vec![0; iv_len];
    rand::thread_rng().fill(&mut iv[..]);
    iv
}

// Encrypt function with proper IV handling
fn encrypt(data: &str, key: &str) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let iv = generate_iv(cipher);

    let mut key_bytes = key.as_bytes().to_vec();
    key_bytes.resize(32, 0); // Ensure 32 bytes

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key_bytes, Some(&iv)).ok()?;
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    
    let count = crypter.update(data.as_bytes(), &mut encrypted).ok()?;
    let rest = crypter.finalize(&mut encrypted[count..]).ok()?;
    
    encrypted.truncate(count + rest);

    let mut result = iv;
    result.extend_from_slice(&encrypted);
    Some(result)
}

// Decrypt function
fn decrypt(data: &[u8], key: &str) -> Option<String> {
    let cipher = Cipher::aes_256_cbc();
    let iv_len = cipher.iv_len().unwrap();

    if data.len() < iv_len {
        return None;
    }

    let (iv, encrypted_data) = data.split_at(iv_len);
    
    let mut key_bytes = key.as_bytes().to_vec();
    key_bytes.resize(32, 0);

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key_bytes, Some(iv)).ok()?;
    let mut decrypted = vec![0; encrypted_data.len() + cipher.block_size()];
    
    let count = crypter.update(encrypted_data, &mut decrypted).ok()?;
    let rest = crypter.finalize(&mut decrypted[count..]).ok()?;
    
    decrypted.truncate(count + rest);
    String::from_utf8(decrypted).ok()
}

// Shared state for storing encrypted data
struct AppState {
    medical_data: Mutex<HashMap<String, Vec<u8>>>,
}

// Store data
async fn store_data(data: web::Json<StoreData>, state: web::Data<AppState>) -> impl Responder {
    let encrypted_data = match encrypt(&data.data, &data.key) {
        Some(enc) => enc,
        None => return HttpResponse::InternalServerError().json(ResponseData { message: "Encryption failed".to_string() }),
    };

    let mut medical_data = state.medical_data.lock().unwrap();
    medical_data.insert(data.id.clone(), encrypted_data);

    HttpResponse::Ok().json(ResponseData { message: format!("Data stored for ID: {}", data.id) })
}

// Retrieve data
async fn retrieve_data(id: web::Path<String>, query: web::Query<RetrieveQuery>, state: web::Data<AppState>) -> impl Responder {
    let medical_data = state.medical_data.lock().unwrap();
    if let Some(encrypted_data) = medical_data.get(&id.into_inner()) {
        match decrypt(encrypted_data, &query.key) {
            Some(decrypted_data) => HttpResponse::Ok().json(ResponseData { message: decrypted_data }),
            None => HttpResponse::Unauthorized().json(ResponseData { message: "Decryption failed".to_string() }),
        }
    } else {
        HttpResponse::NotFound().json(ResponseData { message: "Data not found".to_string() })
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
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
