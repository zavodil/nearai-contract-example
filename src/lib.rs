use near_sdk::{borsh::{BorshDeserialize, BorshSerialize}, log, near_bindgen, serde::Serialize, PanicOnDefault, env, bs58};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use std::fmt::Write;
mod events;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Contract {
    pub public_key: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct CompletionSignaturePayload {
    pub agent_name: String,
    pub model: String,
    pub messages: String,
    pub temperature: Option<u32>,
    pub max_tokens: Option<u32>,
    pub completion: String,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(public_key: String) -> Self {
        Self {
            public_key: public_key[8..].to_string()
        }
    }

    pub fn run_agent(&mut self, agent: String, message: String) {
        events::emit::run_agent(&agent, &message);
    }

    pub fn verify(&self, 
                  signature: String,
                  agent_name: String,
                  model: String,
                  messages: String,
                  temperature: Option<f64>, 
                  max_tokens: Option<u32>,
                  completion: String,
                  verbose: Option<bool> ) -> bool {

        let verbose = verbose.unwrap_or(false);

        // Create the payload structure using the provided parameters such as agent name,
        // completion text, model, messages, temperature, and max tokens.
        // This payload will later be serialized and used for signature verification.
        let payload: &CompletionSignaturePayload = &create_payload(agent_name.as_str(), completion.as_str(), model.as_str(), messages.as_str(), temperature, max_tokens);

        // 1. Serialize the payload using Borsh
        let mut borsh_payload = Vec::new();
        payload.serialize(&mut borsh_payload).unwrap();

        if verbose {
            let message = base64.encode(borsh_payload.clone());
            log!("Base64 payload: {}", message);
        }

        // 2. Compute the SHA-256 hash of the Borsh-serialized data
        let mut hasher = Sha256::new();
        hasher.update(&borsh_payload);
        let to_sign = hasher.finalize();
        if verbose {
            log!("Message to sign: {:?}", to_sign);
        }

        // 3. Decode the public key from Base58
        let pk_bytes = bs58::decode(&self.public_key.as_str()).into_vec().unwrap();
        if pk_bytes.len() != 32 {
            panic!("Invalid public key length");
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);

        // 4. Decode the signature from Base64
        let sig_bytes = base64.decode(signature).unwrap();
        if sig_bytes.len() != 64 {
            panic!("Signature check failed");
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        if verbose {
            log!("Signature: {:?}", sig);
            log!("Public Key: {:?}", pk);
            let sig_bytes = sig.iter().fold(String::new(), |mut acc, &byte| {
                write!(&mut acc, "\\x{:02x}", byte).unwrap();
                acc
            });
            log!("Signature bytes: b\"{}\"", sig_bytes);
        }

        // 5. Validate the signature using `near_sdk::env::ed25519_verify`
        let verification = env::ed25519_verify(
            &sig,
            &to_sign,
            &pk
        );

        if verbose {
            log!("Verification: {:?}", verification);
        }

        assert!(verification, "Signature check failed");

        verification

    }

}

fn create_payload(
    agent_name: &str,
    completion: &str,
    model: &str,
    messages: &str,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
) -> CompletionSignaturePayload {
    // Convert temperature to u32
    let temperature = temperature.map(|temp| (temp * 1000.0).round() as u32);

    CompletionSignaturePayload {
        agent_name: agent_name.to_string(),
        model: model.to_string(),
        messages: messages.to_string(),
        temperature,
        max_tokens,
        completion: completion.to_string(),
    }
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct Message {
    role: String,
    content: String,
}

fn format_messages(messages: &[Message]) -> String {
    let messages_json: Vec<String> = messages
        .iter()
        .map(|m| format!(r#"{{"role": "{}", "content": "{}"}}"#, m.role, m.content))
        .collect();
    format!("[{}]", messages_json.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "BBNDojYRtYDc5vEtzSz69Z9P8EcLCT6DLAzv3pwGkge9";

    #[test]
    pub fn test_verify_messages_string() {
        let contract = Contract { public_key: PUBLIC_KEY.to_string() };

        let signature: &str = "she7TErA273+1imcqyWFN68mgT79cSNJKqb0PHJcOwUSdP3K81x7y2ppPZN4WHd5vaYulzWDF2FZXqc7NyIYCA==";


        let agent_name = "zavodil.near/signed-completions/0.13";
        let completion = "Pineapple pizza is the best.";
        let model = "fireworks::accounts/fireworks/models/llama-v3p1-70b-instruct";
        let messages = r#"[{"role": "system", "content": "Generate random reply"}, {"role": "user", "content": "Test"}]"#;
        let temperature = Some(0.9);
        let max_tokens = Some(512);


        contract.verify(signature.to_string(), agent_name.to_string(), model.to_string(), messages.to_string(), temperature, max_tokens, completion.to_string(), Some(true));
    }

    #[test]
    pub fn test_verify_messages_object() {
        let contract = Contract { public_key: PUBLIC_KEY.to_string() };

        let signature: &str = "she7TErA273+1imcqyWFN68mgT79cSNJKqb0PHJcOwUSdP3K81x7y2ppPZN4WHd5vaYulzWDF2FZXqc7NyIYCA==";
        

        let agent_name = "zavodil.near/signed-completions/0.13";
        let completion = "Pineapple pizza is the best.";
        let model = "fireworks::accounts/fireworks/models/llama-v3p1-70b-instruct";
        let messages = vec![
            Message {
                role: "system".to_string(),
                content: "Generate random reply".to_string(),
            },
            Message {
                role: "user".to_string(),
                content: "Test".to_string(),
            },
        ];
        let temperature = Some(0.9);
        let max_tokens = Some(512);

        let messages_json = format_messages(&messages);


        contract.verify(signature.to_string(), agent_name.to_string(), model.to_string(), messages_json, temperature, max_tokens, completion.to_string(), None);
    }
}

