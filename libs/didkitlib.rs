use std::fs::File;
use std::str::FromStr;
use std::{fs::OpenOptions, io::BufWriter, sync::Arc};
use std::io::{self, BufRead, Write};

use didkit::{CredentialOrJWT, DIDResolver};
use ethereum_types::{H256, U256};
use ethers::{core::k256::{ecdsa::SigningKey, Secp256k1}, middleware::SignerMiddleware, providers::{Http, Middleware, Provider}, signers::{LocalWallet, Signer, Wallet}, types::TransactionRequest};
use serde_json::{from_str, Value};

pub async fn create_vc(
    key: &ssi::jwk::JWK,
    resolver: &dyn DIDResolver,
    did_issuer: &str,
    verification_method: &str

) -> anyhow::Result<String> {
    let vc = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            {
              "@version": 1.1,
              "@vocab": "https://www.w3.org/2018/credentials#",
              "hash": "https://schema.org/identifier"
            }
          ],
        "type": "VerifiableCredential",
        "issuer": "did:key:z6MkjF6Srb2uTSHVtjA53e59pUWJEY2QZzMkh9w198mhZmzB",
        "issuanceDate": ssi::ldp::now_ns(),
        "credentialSubject": {
            "id": "urn:uuid:".to_string() + &uuid::Uuid::new_v4().to_string(),
            "hash": null
        }
    });
    let mut vc: ssi::vc::Credential = serde_json::from_value(vc).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:key:z6MkjF6Srb2uTSHVtjA53e59pUWJEY2QZzMkh9w198mhZmzB#z6MkjF6Srb2uTSHVtjA53e59pUWJEY2QZzMkh9w198mhZmzB".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let mut jwt: String = "".to_string();
    
    proof_options.created = None;
    proof_options.checks = None;
    jwt = vc
        .generate_jwt(Some(&key), &proof_options, resolver)
        .await
        .unwrap();
    Ok(jwt)
}

pub async fn create_vc_withash(
    key: &ssi::jwk::JWK,
    resolver: &dyn DIDResolver,
    did_issuer: &str,
    verification_method: &str,
    hash: &str

) -> anyhow::Result<String> {
    let vc = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            {
              "@version": 1.1,
              "@vocab": "https://www.w3.org/2018/credentials#",
              "hash": "https://schema.org/identifier"
            }
          ],
        "type": "VerifiableCredential",
        "issuer": did_issuer,
        "issuanceDate": ssi::ldp::now_ns(),
        "credentialSubject": {
            "id": "urn:uuid:".to_string() + &uuid::Uuid::new_v4().to_string(),
            "hash": hash
        }
    });
    let mut vc: ssi::vc::Credential = serde_json::from_value(vc).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method.to_owned()));
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let mut jwt: String = "".to_string();
    
    proof_options.created = None;
    proof_options.checks = None;
    jwt = vc
        .generate_jwt(Some(&key), &proof_options, resolver)
        .await
        .unwrap();
    Ok(jwt)
}

pub async fn create_vp(
    key: &ssi::jwk::JWK,
    resolver: &dyn DIDResolver,
    verification_method: &str,
    vc: &CredentialOrJWT,
    did_holder: &str

) -> anyhow::Result<String> {
    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "holder": did_holder,
        "verifiableCredential": vc
    });
    let mut vp: ssi::vc::Presentation = serde_json::from_value(vp).unwrap();
    
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method.to_owned()));
    proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    proof_options.challenge = Some("example".to_string());

    let mut context_loader = ssi::jsonld::ContextLoader::default();
    
    proof_options.created = None;
    proof_options.checks = None;
    let jwt = vp
        .generate_jwt(Some(&key), &proof_options, resolver)
        .await
        .unwrap();

    Ok(jwt)
}

pub async fn verify_vc(
    vc: &str,
    resolver: &dyn DIDResolver
) -> anyhow::Result<i32> {
    let mut num = 0;
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result =
        ssi::vc::Credential::verify_jwt(&vc, None, resolver, &mut context_loader).await;
    if !result.errors.is_empty() {
        num = 1;
    }
    Ok(num)
}

pub async fn verify_vp(
    vp: &str,
    resolver: &dyn DIDResolver
) -> anyhow::Result<i32> {
    let mut num = 0;
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result =
        ssi::vc::Credential::verify_jwt(&vp, None, resolver, &mut context_loader).await;
    if !result.errors.is_empty() {
        num = 1;
    }
    Ok(num)
}

pub async fn recover_previous_vc(
    jwt: &str,
    key: &ssi::jwk::JWK,
    provider: &Arc<Provider<Http>>,
    wallet: &LocalWallet,
    chainid: &str

) -> anyhow::Result<String> {
    let chain_id = chainid.parse::<u64>().unwrap();
    let wallet = wallet.clone().with_chain_id(chain_id);
    let mut result = "".to_string();
    let newprovider = provider.clone();
    let client = Arc::new(SignerMiddleware::new(newprovider, wallet));
    let vc = ssi::vc::Credential::from_jwt(&jwt, &key).unwrap();
    let mut buffer = Vec::new();
    {
        let writer = BufWriter::new(&mut buffer);
        serde_json::to_writer_pretty(writer, &vc).unwrap();
    }
    let json_string = String::from_utf8(buffer).unwrap();
    println!("{}", json_string);

    // Parsa la stringa JSON in un valore serde_json::Value
    let data: Value = serde_json::from_str(&json_string).unwrap();
    let hash = data["credentialSubject"]["hash"].as_str().unwrap_or("Nessun hash");

    let tx_hash = hash.parse::<H256>().unwrap();
    if let Some(transaction) = client.get_transaction(tx_hash).await? {
        let data = transaction.input;
        let recovered_message = String::from_utf8_lossy(&data);
        let vc1 = ssi::vc::Credential::from_jwt(&recovered_message, &key).unwrap();
        println!("Recovered message: {}", recovered_message);
        let mut buffer = Vec::new();
        {
            let writer = BufWriter::new(&mut buffer);
            serde_json::to_writer_pretty(writer, &vc1).unwrap();
        }
        let result = String::from_utf8(buffer).unwrap();
        println!("{}", json_string);
    } else {
        println!("Transaction not found");
    }

    Ok(result)
}

pub async fn recover_previous_hash(
    jwt: &str,
    key: &ssi::jwk::JWK

) -> anyhow::Result<String> {
    let mut result = "".to_string();
    let vc = ssi::vc::Credential::from_jwt(&jwt, &key).unwrap();
    let mut buffer = Vec::new();
    {
        let writer = BufWriter::new(&mut buffer);
        serde_json::to_writer_pretty(writer, &vc).unwrap();
    }
    let json_string = String::from_utf8(buffer).unwrap();
    println!("{}", json_string);

    // Parsa la stringa JSON in un valore serde_json::Value
    let data: Value = serde_json::from_str(&json_string).unwrap();
    let hash = data["credentialSubject"]["hash"].as_str().unwrap_or("Nessun hash");

    Ok(hash.to_string())
}

pub async fn push_tx(
    provider: &Arc<Provider<Http>>,
    wallet: &LocalWallet,
    chainid: &str,
    jwt: &str,
    dest_address: &str
) -> anyhow::Result<H256> {
    let chain_id = chainid.parse::<u64>().unwrap();
    let wallet = wallet.clone().with_chain_id(chain_id);
    let newprovider = provider.clone();
    let client = Arc::new(SignerMiddleware::new(newprovider, wallet));
    let tx = TransactionRequest::new()
        .to(dest_address) // Indirizzo di destinazione fittizio
        .value(U256::zero())
        .data(jwt.as_bytes().to_vec());

    // Invia la transazione
    let pending_tx = client.send_transaction(tx, None).await?;

    // Recupera l'hash della transazione
    let tx_hash = pending_tx.tx_hash();

    Ok(tx_hash)
}

pub async fn write_tx(
    filename: &str,
    tx_hash: &H256
) -> anyhow::Result<i32> {
    let tx = tx_hash.to_string();

    let mut file = OpenOptions::new()
        .append(true)
        .open(filename.to_owned()+".txt")?;

    writeln!(file, "{}", tx)?;

    Ok(0)
}

pub async fn get_tx_list(
    tag: &str
) -> anyhow::Result<Vec<H256>> {
    let file = File::open(tag.to_owned()+".txt")?;
    let reader = io::BufReader::new(file);

    //Creates a vec to contain read line
    let mut lines: Vec<String> = Vec::new();

    //Iter the line of the file and put them into the vec
    for line in reader.lines() {
        let line = line?;
        lines.push(line);
    }

    let mut tx_list: Vec<H256> = Vec::new();

    for line in &lines {
        let tx_hash:H256=H256::from_str(line).unwrap();
        tx_list.push(tx_hash);
    }

    Ok(tx_list)
}

