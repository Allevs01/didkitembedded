use psutil::process::Process;
use sysinfo::{Pid, System};
use tokio;
use async_trait::async_trait;
use ssi_dids::Document;
use ssi_dids::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
    ERROR_NOT_FOUND
};

use std::env;
use std::time::{Duration, Instant};


#[tokio::main]
async fn main()-> Result<(), Box<dyn std::error::Error>>{
    
    let key_str = include_str!("../chiave_str.json");
    
    //funzione per creare vc prendo key, resolver, did_issuer, verification method
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let resolver = &DIDExampleStatic;
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
            "hash": "0xc8740fbb4c62812ad0a1545bd6de0d79f09743758ba5e5400dcd62f4ee66c957",
            "claim1": "value 1",
            "claim2": "value 2",
            "claim3": "value 3",
            "claim4": "value 4",
            "claim5": "value 5",
            "claim6": "value 6",
            "claim7": "value 7",
            "claim8": "value 8",
            "claim9": "value 9",
            "claim10": "value 10"
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
    let mut total_duration = Duration::new(0, 0);

    let mut sys = System::new_all();

    // Aggiorna le informazioni di sistema
    sys.refresh_all();
    // Ottieni il PID del processo corrente e convertilo in un Pid
    let pid = Pid::from(std::process::id() as usize);

    // Ottieni le informazioni sul processo prima dell'esecuzione della funzione
    let process_before = sys.process(pid).expect("Process not found");
    let cpu_usage_before = process_before.cpu_usage();
    let start_time = Instant::now();

    jwt = vc
        .generate_jwt(Some(&key), &proof_options, resolver)
        .await
        .unwrap();
    let result =
        ssi::vc::Credential::verify_jwt(&jwt, None, resolver, &mut context_loader).await;
    if !result.errors.is_empty() {
        panic!("verify failed: {:?}", result);
    }

    // Attendere un breve intervallo di tempo per garantire che le informazioni di sistema siano aggiornate
    std::thread::sleep(Duration::from_millis(100));

    // Aggiorna le informazioni di sistema e ottieni le informazioni sul processo dopo l'esecuzione della funzione
    sys.refresh_all();
    let process_after = sys.process(pid).expect("Process not found");
    let cpu_usage_after = process_after.cpu_usage();
    let duration = start_time.elapsed();

    // Calcola la differenza nell'utilizzo della CPU
    let cpu_usage_diff = cpu_usage_after - cpu_usage_before;

    // Calcola la percentuale di utilizzo della CPU durante l'esecuzione della funzione
    let cpu_percentage = cpu_usage_diff / duration.as_secs_f32() * 100.0;

    
    //start
    for i in 0..10 {
    let start_time = Instant::now();

    jwt = vc
        .generate_jwt(Some(&key), &proof_options, resolver)
        .await
        .unwrap();
    let result =
        ssi::vc::Credential::verify_jwt(&jwt, None, resolver, &mut context_loader).await;
    if !result.errors.is_empty() {
        panic!("verify failed: {:?}", result);
    }

    let end_time = Instant::now();
    //end

    let duration = end_time.duration_since(start_time);
    let duration2 = start_time.elapsed();
    total_duration += duration;

    }
    
    // Calcola la media della durata in millisecondi
    let total_duration_millis = total_duration.as_millis();
    let average_duration_millis = total_duration_millis as f64 / 10.0;

    print!("{}", jwt);
    let vc1 = ssi::vc::Credential::from_jwt(&jwt, &key).unwrap();
    //println!("{:#?}", vc1);
    let stdout_writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(stdout_writer, &vc1).unwrap();

    println!("Average duration in ms: {}", average_duration_millis);
    let jwt_asbytes = jwt.as_bytes();
    println!("Bytes taken by vc: {:?}", jwt_asbytes.len());
    println!("Utilizzo CPU: {:?} ", cpu_percentage);
    //println!("Utilizzo memoria: {:?} byte", memory_usage);

    Ok(())
}


pub struct DIDExampleStatic;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDExampleStatic {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        match did {
            "did:key:z6MkjF6Srb2uTSHVtjA53e59pUWJEY2QZzMkh9w198mhZmzB" => {
                let doc = match Document::from_json(include_str!("../did-example-mine.json")) {
                    Ok(doc) => doc,
                    Err(e) => {
                        return (
                            ResolutionMetadata::from_error(&format!(
                                "Unable to parse DID document: {:?}",
                                e
                            )),
                            None,
                            None,
                        );
                    }
                };
                (
                    ResolutionMetadata::default(),
                    Some(doc),
                    Some(DocumentMetadata::default()),
                )
            }
            _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
        }
    }
}