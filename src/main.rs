use axum::{
    extract::Json,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use solana_program::{
    instruction::Instruction,
    pubkey::Pubkey,
    system_instruction,
};
use solana_sdk::{
    signature::{Keypair as SolanaKeypair, Signature as SolanaSignature, Signer},
};
use spl_token::{
    instruction::{initialize_mint, mint_to, transfer},
};
use std::str::FromStr;
use tower_http::cors::CorsLayer;

// Response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// Request/Response structs
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    #[serde(rename = "is_signer")]
    is_signer: bool,
    #[serde(rename = "is_writable")]
    is_writable: bool,
}

#[derive(Serialize)]
struct SolTransferResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenTransferAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenTransferResponse {
    program_id: String,
    accounts: Vec<TokenTransferAccount>,
    instruction_data: String,
}

// Helper functions
fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|_| "Invalid public key format".to_string())
}

fn instruction_to_response(instruction: &Instruction) -> InstructionResponse {
    InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .iter()
            .map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            })
            .collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }
}

// Endpoint handlers
async fn generate_keypair() -> ResponseJson<ApiResponse<KeypairResponse>> {
    let keypair = SolanaKeypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    ResponseJson(ApiResponse::success(KeypairResponse { pubkey, secret }))
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> ResponseJson<ApiResponse<InstructionResponse>> {
    let mint_authority = match parse_pubkey(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let mint = match parse_pubkey(&payload.mint) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    // Get minimum rent for mint account
    let _rent_exemption_reserve = 1461600; // Approximate rent for mint account

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    )
    .unwrap();

    ResponseJson(ApiResponse::success(instruction_to_response(&instruction)))
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> ResponseJson<ApiResponse<InstructionResponse>> {
    let mint = match parse_pubkey(&payload.mint) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let destination = match parse_pubkey(&payload.destination) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let authority = match parse_pubkey(&payload.authority) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .unwrap();

    ResponseJson(ApiResponse::success(instruction_to_response(&instruction)))
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> ResponseJson<ApiResponse<SignMessageResponse>> {
    // Check for missing fields
    if payload.message.is_empty() || payload.secret.is_empty() {
        return ResponseJson(ApiResponse::error("Missing required fields".to_string()));
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return ResponseJson(ApiResponse::error("Invalid secret key format".to_string())),
    };

    if secret_bytes.len() != 64 {
        return ResponseJson(ApiResponse::error("Invalid secret key length".to_string()));
    }

    let keypair = match SolanaKeypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return ResponseJson(ApiResponse::error("Invalid secret key".to_string())),
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    ResponseJson(ApiResponse::success(SignMessageResponse {
        signature: signature_b64,
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    }))
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> ResponseJson<ApiResponse<VerifyMessageResponse>> {
    let pubkey = match parse_pubkey(&payload.pubkey) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return ResponseJson(ApiResponse::error("Invalid signature format".to_string())),
    };

    let signature = match SolanaSignature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return ResponseJson(ApiResponse::error("Invalid signature".to_string())),
    };

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    ResponseJson(ApiResponse::success(VerifyMessageResponse {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    }))
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> ResponseJson<ApiResponse<SolTransferResponse>> {
    let from = match parse_pubkey(&payload.from) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let to = match parse_pubkey(&payload.to) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    // Validate lamports amount (must be positive)
    if payload.lamports == 0 {
        return ResponseJson(ApiResponse::error("Invalid lamports amount".to_string()));
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    ResponseJson(ApiResponse::success(SolTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .iter()
            .map(|acc| acc.pubkey.to_string())
            .collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }))
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> ResponseJson<ApiResponse<TokenTransferResponse>> {
    let mint = match parse_pubkey(&payload.mint) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let owner = match parse_pubkey(&payload.owner) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    let destination = match parse_pubkey(&payload.destination) {
        Ok(pk) => pk,
        Err(e) => return ResponseJson(ApiResponse::error(e)),
    };

    // For token transfers, we need the associated token accounts
    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let dest_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        payload.amount,
    )
    .unwrap();

    ResponseJson(ApiResponse::success(TokenTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .iter()
            .map(|acc| TokenTransferAccount {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
            })
            .collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    
    axum::serve(listener, app).await.unwrap();
}