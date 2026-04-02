///! Vote Producer — Voter Client CLI.
///!
///! Simulates a voter:
///!   1. Takes a vote value (0 or 1, representing yes/no or candidate selection).
///!   2. Generates a Pedersen commitment to the vote.
///!   3. Constructs a Bulletproof range proof proving the vote is valid.
///!   4. Transmits the (Commitment, Proof) payload to the Consumer Service.

use k256::{ProjectivePoint, AffinePoint, Scalar};
use elliptic_curve::sec1::ToEncodedPoint;

use std::env;

use crypto_primitives::generators::BulletproofGens;
use bulletproofs_core::range_proof::{prove_range, RangeProof};
use bulletproofs_core::inner_product::InnerProductProof;

use serde::{Serialize, Deserialize};

/// CLI arguments parsed from std::env.
struct Args {
    vote: u64,
    server: String,
    bits: usize,
    dry_run: bool,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut vote: Option<u64> = None;
        let mut server = "http://127.0.0.1:8080".to_string();
        let mut bits: usize = 8;
        let mut dry_run = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--vote" | "-v" => {
                    i += 1;
                    vote = Some(args[i].parse().expect("vote must be a number"));
                }
                "--server" | "-s" => {
                    i += 1;
                    server = args[i].clone();
                }
                "--bits" | "-b" => {
                    i += 1;
                    bits = args[i].parse().expect("bits must be a number");
                }
                "--dry-run" => {
                    dry_run = true;
                }
                "--help" | "-h" => {
                    eprintln!("Usage: vote-producer --vote <VALUE> [--server <URL>] [--bits <N>] [--dry-run]");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        let vote = vote.expect("--vote is required");
        Args { vote, server, bits, dry_run }
    }
}

// ─── Wire types (must match consumer_service) ──────────────────────────────

fn point_to_hex(p: &ProjectivePoint) -> String {
    let affine: AffinePoint = (*p).into();
    hex::encode(affine.to_encoded_point(true).as_bytes())
}

fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

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
}

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
}

#[derive(Serialize, Deserialize)]
pub struct VotePayload {
    pub commitment: String,
    pub proof: RangeProofWire,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VoteResponse {
    pub accepted: bool,
    pub message: String,
    pub vote_index: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("=== ZKP Election Vote Producer ===");
    println!("Vote value: {}", args.vote);
    println!("Range bits: {}", args.bits);

    // Validate vote is in range
    if args.vote >= (1u64 << args.bits) {
        eprintln!("Error: vote value {} is out of range [0, {})", args.vote, 1u64 << args.bits);
        std::process::exit(1);
    }

    // Generate generators (same parameters as consumer)
    println!("Generating cryptographic parameters...");
    let gens = BulletproofGens::new(args.bits);

    // Generate proof
    println!("Constructing Bulletproof range proof...");
    let (commitment, proof) = prove_range(&gens, args.vote, args.bits);

    println!("Proof generated successfully!");
    println!("  Commitment: {}", &point_to_hex(&commitment.point)[..16]);
    println!("  IPP rounds: {}", proof.ipp_proof.l_vec.len());

    // Build payload
    let payload = VotePayload {
        commitment: point_to_hex(&commitment.point),
        proof: RangeProofWire::from_proof(&proof),
    };

    if args.dry_run {
        println!("\n[dry-run] Proof payload (JSON):");
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    // Submit to consumer service
    let url = format!("{}/vote", args.server);
    println!("\nSubmitting vote to {}...", url);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await?;

    if resp.status().is_success() {
        let vote_resp: VoteResponse = resp.json().await?;
        println!("Response: {:?}", vote_resp);
        if vote_resp.accepted {
            println!("Vote accepted! Index: {:?}", vote_resp.vote_index);
        } else {
            println!("Vote rejected: {}", vote_resp.message);
        }
    } else {
        let status = resp.status();
        let body = resp.text().await?;
        eprintln!("Server error ({}): {}", status, body);
    }

    Ok(())
}
