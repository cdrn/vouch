//! End-to-end DKG and sign: boot a relay + a signer service, run DKG,
//! then sign a message, and verify the aggregated signature on both
//! sides plus against the joint verifying key.

use tokio::net::TcpListener;
use vouch_frost::{KeyPackage, PublicKeyPackage};
use vouch_signer::api::{DkgRequest, DkgResponse, SignRequest, SignResponse};
use vouch_signer::ceremony::{run_dkg, run_sign};

async fn boot_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, vouch_relay::router()).await.unwrap();
    });
    format!("ws://{}/ws", addr)
}

async fn boot_signer() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, vouch_signer::router()).await.unwrap();
    });
    format!("http://{}", addr)
}

async fn dkg_via_http(
    signer_url: &str,
    relay_url: &str,
    session: &str,
    client_id: u16,
    signer_id: u16,
) -> (DkgResponse, KeyPackage, PublicKeyPackage) {
    let dkg_req = DkgRequest {
        session: session.to_string(),
        relay_url: relay_url.to_string(),
        signer_participant: signer_id,
        client_participant: client_id,
        h_passport_hex: None,
    };

    let signer_call_url = format!("{signer_url}/v0/dkg");
    let signer_fut = {
        let dkg_req = dkg_req.clone();
        tokio::spawn(async move {
            let resp = reqwest::Client::new()
                .post(&signer_call_url)
                .json(&dkg_req)
                .send()
                .await
                .expect("post failed");
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            assert!(status.is_success(), "signer returned {status}: {body}");
            serde_json::from_str::<DkgResponse>(&body).expect("decode dkg response")
        })
    };

    let client_fut = {
        let relay_url = relay_url.to_string();
        let session = session.to_string();
        tokio::spawn(async move {
            run_dkg(&relay_url, &session, client_id, signer_id)
                .await
                .expect("client dkg")
        })
    };

    let (signer_resp, client_result) = tokio::join!(signer_fut, client_fut);
    let signer_resp = signer_resp.expect("signer task panicked");
    let (client_key, client_pub) = client_result.expect("client task panicked");
    (signer_resp, client_key, client_pub)
}

#[tokio::test]
async fn signer_completes_dkg_via_relay() {
    let relay_url = boot_relay().await;
    let signer_url = boot_signer().await;

    let (signer_resp, _client_key, client_pub) =
        dkg_via_http(&signer_url, &relay_url, "dkg-test-1", 1, 2).await;

    let client_vkey_bytes = postcard::to_stdvec(client_pub.verifying_key()).unwrap();
    let client_vkey_hex = hex::encode(&client_vkey_bytes);

    assert_eq!(
        signer_resp.joint_pubkey_hex, client_vkey_hex,
        "client and signer must converge on the same joint pubkey"
    );
}

#[tokio::test]
async fn signer_completes_sign_via_relay() {
    let relay_url = boot_relay().await;
    let signer_url = boot_signer().await;

    let client_id: u16 = 1;
    let signer_id: u16 = 2;

    // 1) DKG so the signer has a key package to sign with.
    let (dkg_resp, client_key, client_pub) =
        dkg_via_http(&signer_url, &relay_url, "sign-test-dkg", client_id, signer_id)
            .await;

    // 2) Sign over a fresh session.
    let session = "sign-test-1";
    let message = b"vouch userop hash".to_vec();

    let sign_req = SignRequest {
        account_pubkey_hex: dkg_resp.joint_pubkey_hex.clone(),
        session: session.to_string(),
        relay_url: relay_url.clone(),
        signer_participant: signer_id,
        client_participant: client_id,
        message: message.clone(),
    };

    let signer_call_url = format!("{signer_url}/v0/sign");
    let signer_fut = {
        let sign_req = sign_req.clone();
        tokio::spawn(async move {
            let resp = reqwest::Client::new()
                .post(&signer_call_url)
                .json(&sign_req)
                .send()
                .await
                .expect("post failed");
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            assert!(status.is_success(), "signer returned {status}: {body}");
            serde_json::from_str::<SignResponse>(&body).expect("decode sign response")
        })
    };

    let client_fut = {
        let relay_url = relay_url.clone();
        let session = session.to_string();
        let message = message.clone();
        let client_key = client_key.clone();
        let client_pub = client_pub.clone();
        tokio::spawn(async move {
            run_sign(
                &relay_url,
                &session,
                client_id,
                signer_id,
                &client_key,
                &client_pub,
                &message,
            )
            .await
            .expect("client sign")
        })
    };

    let (signer_resp, client_sig) = tokio::join!(signer_fut, client_fut);
    let signer_resp = signer_resp.expect("signer task panicked");
    let client_sig = client_sig.expect("client task panicked");

    // Both sides aggregated independently — they must match bit-for-bit.
    let client_sig_bytes = postcard::to_stdvec(&client_sig).unwrap();
    assert_eq!(
        signer_resp.signature_hex,
        hex::encode(&client_sig_bytes),
        "signer and client must aggregate to the same signature"
    );

    // And it must verify against the joint pubkey.
    client_pub
        .verifying_key()
        .verify(&message, &client_sig)
        .expect("signature must verify under joint pubkey");
}
