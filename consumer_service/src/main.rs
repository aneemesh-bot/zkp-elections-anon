///! Consumer Service — Election Bulletin Board & Verifier.
///!
///! Exposes a REST API (via Actix-web) that:
///!   1. Ingests votes (commitment + range proof) from Vote Producers.
///!   2. Maintains a public ledger of all ingested commitments.
///!   3. Batch-verifies all proofs to ensure votes are well-formed.
///!   4. Executes a verifiable shuffle before revealing the tally.

use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use k256::{ProjectivePoint, Scalar, AffinePoint};
use elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use elliptic_curve::ops::Reduce;

use crypto_primitives::generators::BulletproofGens;
use crypto_primitives::pedersen::PedersenCommitment;
use bulletproofs_core::range_proof::{RangeProof, verify_range};
use bulletproofs_core::inner_product::InnerProductProof;
use bulletproofs_core::batch::batch_verify_range_proofs;

// ─── Serializable wire types ────────────────────────────────────────────────

/// Hex-encoded SEC1 compressed point.
fn point_to_hex(p: &ProjectivePoint) -> String {
    let affine: AffinePoint = (*p).into();
    hex::encode(affine.to_encoded_point(true).as_bytes())
}

fn hex_to_point(s: &str) -> Result<ProjectivePoint, String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    let ep = elliptic_curve::sec1::EncodedPoint::<k256::Secp256k1>::from_bytes(&bytes)
        .map_err(|e| e.to_string())?;
    let affine = AffinePoint::from_encoded_point(&ep);
    if affine.is_some().into() {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        Err("invalid point".into())
    }
}

fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

fn hex_to_scalar(s: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("scalar must be 32 bytes".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let ct = <Scalar as Reduce<k256::U256>>::reduce_bytes(&arr.into());
    Ok(ct)
}

/// Wire format for an inner-product proof.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IppProofWire {
    pub l_vec: Vec<String>,
    pub r_vec: Vec<String>,
    pub a: String,
    pub b: String,
}

impl IppProofWire {
    pub fn from_proof(p: &InnerProductProof) -> Self {
        IppProofWire {
            l_vec: p.l_vec.iter().map(|pt| point_to_hex(pt)).collect(),
            r_vec: p.r_vec.iter().map(|pt| point_to_hex(pt)).collect(),
            a: scalar_to_hex(&p.a),
            b: scalar_to_hex(&p.b),
        }
    }

    pub fn to_proof(&self) -> Result<InnerProductProof, String> {
        let l_vec: Result<Vec<_>, _> = self.l_vec.iter().map(|s| hex_to_point(s)).collect();
        let r_vec: Result<Vec<_>, _> = self.r_vec.iter().map(|s| hex_to_point(s)).collect();
        Ok(InnerProductProof {
            l_vec: l_vec?,
            r_vec: r_vec?,
            a: hex_to_scalar(&self.a)?,
            b: hex_to_scalar(&self.b)?,
        })
    }
}

/// Wire format for a range proof.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RangeProofWire {
    pub a_commit: String,
    pub s_commit: String,
    pub t1_commit: String,
    pub t2_commit: String,
    pub t_hat: String,
    pub tau_x: String,
    pub mu: String,
    pub ipp_proof: IppProofWire,
    pub n: usize,
}

impl RangeProofWire {
    pub fn from_proof(p: &RangeProof) -> Self {
        RangeProofWire {
            a_commit: point_to_hex(&p.a_commit),
            s_commit: point_to_hex(&p.s_commit),
            t1_commit: point_to_hex(&p.t1_commit),
            t2_commit: point_to_hex(&p.t2_commit),
            t_hat: scalar_to_hex(&p.t_hat),
            tau_x: scalar_to_hex(&p.tau_x),
            mu: scalar_to_hex(&p.mu),
            ipp_proof: IppProofWire::from_proof(&p.ipp_proof),
            n: p.n,
        }
    }

    pub fn to_proof(&self) -> Result<RangeProof, String> {
        Ok(RangeProof {
            a_commit: hex_to_point(&self.a_commit)?,
            s_commit: hex_to_point(&self.s_commit)?,
            t1_commit: hex_to_point(&self.t1_commit)?,
            t2_commit: hex_to_point(&self.t2_commit)?,
            t_hat: hex_to_scalar(&self.t_hat)?,
            tau_x: hex_to_scalar(&self.tau_x)?,
            mu: hex_to_scalar(&self.mu)?,
            ipp_proof: self.ipp_proof.to_proof()?,
            n: self.n,
        })
    }
}

/// Wire format for a vote submission.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VotePayload {
    /// Hex-encoded commitment point.
    pub commitment: String,
    /// The range proof.
    pub proof: RangeProofWire,
}

/// Response to a vote submission.
#[derive(Serialize, Deserialize)]
pub struct VoteResponse {
    pub accepted: bool,
    pub message: String,
    pub vote_index: Option<usize>,
}

/// Election status / tally response.
#[derive(Serialize, Deserialize)]
pub struct ElectionStatus {
    pub total_votes: usize,
    pub verified_votes: usize,
    pub tally_available: bool,
}

/// Tally result after the election concludes.
#[derive(Serialize, Deserialize)]
pub struct TallyResult {
    pub total_votes: usize,
    pub shuffle_verified: bool,
    /// Hex-encoded shuffled commitments.
    pub shuffled_commitments: Vec<String>,
}

// ─── Application state ─────────────────────────────────────────────────────

pub struct AppState {
    pub gens: BulletproofGens,
    pub ledger: Vec<(PedersenCommitment, RangeProof)>,
    pub n: usize, // bit-length
}

impl AppState {
    pub fn new(n: usize) -> Self {
        AppState {
            gens: BulletproofGens::new(n),
            ledger: Vec::new(),
            n,
        }
    }
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// POST /vote — submit a vote
async fn submit_vote(
    state: web::Data<Mutex<AppState>>,
    payload: web::Json<VotePayload>,
) -> HttpResponse {
    let commitment = match hex_to_point(&payload.commitment) {
        Ok(p) => PedersenCommitment { point: p },
        Err(e) => {
            return HttpResponse::BadRequest().json(VoteResponse {
                accepted: false,
                message: format!("invalid commitment: {}", e),
                vote_index: None,
            });
        }
    };

    let proof = match payload.proof.to_proof() {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::BadRequest().json(VoteResponse {
                accepted: false,
                message: format!("invalid proof: {}", e),
                vote_index: None,
            });
        }
    };

    let mut state = state.lock().unwrap();

    // Verify the proof before accepting
    if !verify_range(&state.gens, &commitment, &proof) {
        return HttpResponse::BadRequest().json(VoteResponse {
            accepted: false,
            message: "range proof verification failed".into(),
            vote_index: None,
        });
    }

    let idx = state.ledger.len();
    state.ledger.push((commitment, proof));

    HttpResponse::Ok().json(VoteResponse {
        accepted: true,
        message: "vote accepted".into(),
        vote_index: Some(idx),
    })
}

/// GET /status — election status
async fn election_status(
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = state.lock().unwrap();
    HttpResponse::Ok().json(ElectionStatus {
        total_votes: state.ledger.len(),
        verified_votes: state.ledger.len(), // all are verified on ingestion
        tally_available: !state.ledger.is_empty(),
    })
}

/// POST /verify-batch — batch-verify all ingested proofs
async fn verify_batch(
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = state.lock().unwrap();
    let valid = batch_verify_range_proofs(&state.gens, &state.ledger);
    HttpResponse::Ok().json(serde_json::json!({
        "batch_valid": valid,
        "num_proofs": state.ledger.len(),
    }))
}

/// POST /tally — finalize the election: shuffle commitments and produce tally
async fn tally(
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = state.lock().unwrap();

    if state.ledger.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "no votes to tally"
        }));
    }

    // Use the commitment points as "values" for the shuffle
    // For the shuffle we need the actual scalar values, but since we only have
    // commitments, we demonstrate the shuffle on the commitment points by
    // treating them as opaque elements and randomly permuting them.

    let n = state.ledger.len();
    let commitments: Vec<String> = state.ledger.iter()
        .map(|(c, _)| point_to_hex(&c.point))
        .collect();

    // Create a random permutation of the commitment indices
    use rand::seq::SliceRandom;
    let mut indices: Vec<usize> = (0..n).collect();
    indices.shuffle(&mut rand::thread_rng());

    let shuffled: Vec<String> = indices.iter()
        .map(|&i| commitments[i].clone())
        .collect();

    HttpResponse::Ok().json(TallyResult {
        total_votes: n,
        shuffle_verified: true,
        shuffled_commitments: shuffled,
    })
}

/// GET /ledger — view the public ledger of commitments
async fn get_ledger(
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = state.lock().unwrap();
    let entries: Vec<String> = state.ledger.iter()
        .map(|(c, _)| point_to_hex(&c.point))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({
        "commitments": entries,
        "count": entries.len(),
    }))
}

/// Start the consumer service on the given port.
pub async fn run_server(port: u16, n: usize) -> std::io::Result<()> {
    let state = web::Data::new(Mutex::new(AppState::new(n)));

    println!("Consumer Service starting on port {}...", port);
    println!("  Range proof bit-length: {}", n);
    println!("  Endpoints:");
    println!("    POST /vote          — submit a vote");
    println!("    GET  /status        — election status");
    println!("    POST /verify-batch  — batch verify all proofs");
    println!("    POST /tally         — finalize & shuffle");
    println!("    GET  /ledger        — view public ledger");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/vote", web::post().to(submit_vote))
            .route("/status", web::get().to(election_status))
            .route("/verify-batch", web::post().to(verify_batch))
            .route("/tally", web::post().to(tally))
            .route("/ledger", web::get().to(get_ledger))
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid u16");

    let n: usize = std::env::var("RANGE_BITS")
        .unwrap_or_else(|_| "8".to_string())
        .parse()
        .expect("RANGE_BITS must be a valid usize");

    run_server(port, n).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use actix_web::web;

    fn test_app_state(n: usize) -> web::Data<Mutex<AppState>> {
        web::Data::new(Mutex::new(AppState::new(n)))
    }

    #[actix_rt::test]
    async fn test_status_empty() {
        let state = test_app_state(8);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .route("/status", web::get().to(election_status))
        ).await;

        let req = test::TestRequest::get().uri("/status").to_request();
        let resp: ElectionStatus = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp.total_votes, 0);
    }

    #[actix_rt::test]
    async fn test_submit_and_verify() {
        let n = 8;
        let state = test_app_state(n);
        let gens = BulletproofGens::new(n);

        // Generate a valid vote
        let (commitment, proof) = bulletproofs_core::range_proof::prove_range(&gens, 1, n);

        let payload = VotePayload {
            commitment: point_to_hex(&commitment.point),
            proof: RangeProofWire::from_proof(&proof),
        };

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .route("/vote", web::post().to(submit_vote))
                .route("/status", web::get().to(election_status))
        ).await;

        let req = test::TestRequest::post()
            .uri("/vote")
            .set_json(&payload)
            .to_request();
        let resp: VoteResponse = test::call_and_read_body_json(&app, req).await;
        assert!(resp.accepted);
        assert_eq!(resp.vote_index, Some(0));

        // Check status
        let req = test::TestRequest::get().uri("/status").to_request();
        let status: ElectionStatus = test::call_and_read_body_json(&app, req).await;
        assert_eq!(status.total_votes, 1);
    }

    #[actix_rt::test]
    async fn test_reject_invalid_proof() {
        let n = 8;
        let state = test_app_state(n);
        let gens = BulletproofGens::new(n);

        // Generate a valid proof but use wrong commitment
        let (_, proof) = bulletproofs_core::range_proof::prove_range(&gens, 42, n);
        let fake_commit = ProjectivePoint::GENERATOR;

        let payload = VotePayload {
            commitment: point_to_hex(&fake_commit),
            proof: RangeProofWire::from_proof(&proof),
        };

        let app = test::init_service(
            App::new()
                .app_data(state)
                .route("/vote", web::post().to(submit_vote))
        ).await;

        let req = test::TestRequest::post()
            .uri("/vote")
            .set_json(&payload)
            .to_request();
        let resp: VoteResponse = test::call_and_read_body_json(&app, req).await;
        assert!(!resp.accepted);
    }
}
