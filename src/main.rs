use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use rand::Rng;
use pbkdf2::{pbkdf2_hmac, Params};
use sha2::Sha256;

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

// Derives a secure 32-byte key using PBKDF2
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key).unwrap();
    key
}

// Encrypt function with IV handling
fn encrypt(data: &str, key: &str) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let iv = generate_iv(cipher);
    
    // Generate a salt and derive a secure key
    let salt = rand::thread_rng().gen::<[u8; 16]>();
    let derived_key = derive_key(key, &salt);

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &derived_key, Some(&iv)).ok()?;
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    
    let count = crypter.update(data.as_bytes(), &mut encrypted).ok()?;
    let rest = crypter.finalize(&mut encrypted[count..]).ok()?;
    encrypted.truncate(count + rest);

    // Store IV, salt, and encrypted data together
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&encrypted);
    Some(result)
}

// Decrypt function with IV handling
fn decrypt(data: &[u8], key: &str) -> Option<String> {
    let cipher = Cipher::aes_256_cbc();
    let iv_len = cipher.iv_len().unwrap();

    if data.len() < iv_len + 16 {
        return None; // Invalid data length
    }

    let (salt, rest) = data.split_at(16);
    let (iv, encrypted_data) = rest.split_at(iv_len);
    
    let derived_key = derive_key(key, salt);

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &derived_key, Some(iv)).ok()?;
    let mut decrypted = vec![0; encrypted_data.len() + cipher.block_size()];
    
    let count = crypter.update(encrypted_data, &mut decrypted).ok()?;
    let rest = crypter.finalize(&mut decrypted[count..]).ok()?;
    decrypted.truncate(count + rest);

    String::from_utf8(decrypted).ok()
}

// Shared state using async RwLock for better concurrency
struct AppState {
    medical_data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

async fn store_data(data: web::Json<StoreData>, state: web::Data<AppState>) -> impl Responder {
    let encrypted_data = match encrypt(&data.data, &data.key) {
        Some(enc) => enc,
        None => return HttpResponse::InternalServerError().body("Encryption failed"),
    };

    let mut medical_data = state.medical_data.write().await;
    medical_data.insert(data.id.clone(), encrypted_data);
    HttpResponse::Ok().body(format!("Data stored securely for ID: {}", data.id))
}

async fn retrieve_data(id: web::Path<String>, query: web::Query<RetrieveQuery>, state: web::Data<AppState>) -> impl Responder {
    let medical_data = state.medical_data.read().await;
    if let Some(encrypted_data) = medical_data.get(&id.into_inner()) {
        match decrypt(encrypted_data, &query.key) {
            Some(decrypted_data) => HttpResponse::Ok().body(format!("Retrieved data: {}", decrypted_data)),
            None => HttpResponse::Unauthorized().body("Decryption failed"),
        }
    } else {
        HttpResponse::NotFound().body("Data not found")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let data = web::Data::new(AppState {
        medical_data: Arc::new(RwLock::new(HashMap::new())),
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
