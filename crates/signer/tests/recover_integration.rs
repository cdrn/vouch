//! /v0/recover: register a wallet with an H_passport at DKG time,
//! then look it up via the recovery endpoint.

use tokio::net::TcpListener;
use vouch_signer::api::{DkgRequest, DkgResponse, RecoverRequest, RecoverResponse};
use vouch_signer::ceremony::run_dkg;

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

#[tokio::test]
async fn recover_finds_account_registered_at_dkg_time() {
    let relay_url = boot_relay().await;
    let signer_url = boot_signer().await;

    let client_id: u16 = 1;
    let signer_id: u16 = 2;
    let session = "recover-test-1".to_string();

    // Pretend H_passport for this account.
    let h_passport_hex =
        "deadbeef".repeat(8); // 32 bytes hex

    let dkg_req = DkgRequest {
        session: session.clone(),
        relay_url: relay_url.clone(),
        signer_participant: signer_id,
        client_participant: client_id,
        h_passport_hex: Some(h_passport_hex.clone()),
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
        let relay_url = relay_url.clone();
        let session = session.clone();
        tokio::spawn(async move {
            run_dkg(&relay_url, &session, client_id, signer_id)
                .await
                .expect("client dkg")
        })
    };

    let (signer_resp, client_result) = tokio::join!(signer_fut, client_fut);
    let signer_resp = signer_resp.expect("signer task panicked");
    let (_client_key, _client_pub) = client_result.expect("client task panicked");

    // Now hit /v0/recover with the same H_passport.
    let recover_url = format!("{signer_url}/v0/recover");
    let recover_resp = reqwest::Client::new()
        .post(&recover_url)
        .json(&RecoverRequest {
            h_passport_hex: h_passport_hex.clone(),
        })
        .send()
        .await
        .expect("recover post failed");
    assert!(recover_resp.status().is_success());
    let body: RecoverResponse = recover_resp.json().await.unwrap();

    assert!(body.matched, "H_passport should match registered account");
    assert_eq!(
        body.account_pubkey_hex, signer_resp.joint_pubkey_hex,
        "recover should resolve to the same account id the DKG produced"
    );
}

#[tokio::test]
async fn recover_returns_no_match_for_unknown_passport() {
    let signer_url = boot_signer().await;

    let unknown_h_passport = "cafebabe".repeat(8);
    let resp = reqwest::Client::new()
        .post(&format!("{signer_url}/v0/recover"))
        .json(&RecoverRequest {
            h_passport_hex: unknown_h_passport,
        })
        .send()
        .await
        .expect("post");
    let body: RecoverResponse = resp.json().await.unwrap();
    assert!(!body.matched);
    assert_eq!(body.account_pubkey_hex, "");
}

#[tokio::test]
async fn recover_rejects_malformed_h_passport() {
    let signer_url = boot_signer().await;

    let resp = reqwest::Client::new()
        .post(&format!("{signer_url}/v0/recover"))
        .json(&RecoverRequest {
            h_passport_hex: "zzzz".into(),
        })
        .send()
        .await
        .expect("post");
    // hex decode error → 500.
    assert!(resp.status().is_server_error());
}
