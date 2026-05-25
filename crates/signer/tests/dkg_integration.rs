//! End-to-end DKG: boot a relay + a signer service, simulate a client
//! that POSTs to the signer and runs the matching DKG role over the
//! same relay session. Verify both parties land on the same joint
//! verifying key.

use tokio::net::TcpListener;
use vouch_signer::api::{DkgRequest, DkgResponse};
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
async fn signer_completes_dkg_via_relay() {
    let relay_url = boot_relay().await;
    let signer_url = boot_signer().await;

    let session = "dkg-test-1".to_string();
    let client_id: u16 = 1;
    let signer_id: u16 = 2;

    let dkg_req = DkgRequest {
        session: session.clone(),
        relay_url: relay_url.clone(),
        signer_participant: signer_id,
        client_participant: client_id,
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
    let (_client_key, client_pub) = client_result.expect("client task panicked");

    let client_vkey_bytes = postcard::to_stdvec(client_pub.verifying_key()).unwrap();
    let client_vkey_hex = hex::encode(&client_vkey_bytes);

    assert_eq!(
        signer_resp.joint_pubkey_hex, client_vkey_hex,
        "client and signer must converge on the same joint pubkey"
    );
}
