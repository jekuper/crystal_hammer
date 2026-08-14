//! Compile-time embedded key material.
//!
//! Per SPECS section 13.5 the tool embeds a **single shared team ed25519 keypair** at build
//! time, and the *same* keypair both signs the SPA knock and authenticates the SSH
//! session. Only the public key is embedded - never a private key (SPECS section 9).
//!
//! The build flow (M0) bakes the operator-provided public and private key in. Until that wiring
//! exists, `TEAM_KEYPAIR_RAW` is empty and [`TeamKeyPair::from_embedded`] returns `None`.

use ed25519_dalek::{SigningKey, VerifyingKey};

/// The embedded team keypair, injected at build time.
///
/// M0 replaces this with `env!("CH_TEAM_KEYPAIR")` (or an `include_bytes!` of a generated
/// file) so a build bakes in the real keypair.
pub const TEAM_KEYPAIR_RAW: &[u8] = include_bytes!("../../../id_rsa");

/// Team keypair with embedded key material.
#[derive(Debug, Clone)]
pub struct TeamKeyPair {
    pub public: VerifyingKey,
    pub secret: SigningKey,
}

impl TeamKeyPair {
    /// Create a new keypair (for testing/dev).
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;

        let secret = SigningKey::generate(&mut rng);
        let public = secret.verifying_key();
        Self { public, secret }
    }

    /// Load from embedded bytes, if present.
    pub fn from_embedded() -> Option<Self> {
        let raw: [u8; 64] = TEAM_KEYPAIR_RAW.try_into().ok()?;
        let secret_bytes: [u8; 32] = raw[..32].try_into().ok()?;
        let public_bytes: [u8; 32] = raw[32..].try_into().ok()?;

        let secret = SigningKey::from_bytes(&secret_bytes);
        let public = VerifyingKey::from_bytes(&public_bytes).ok()?;
        Some(Self { public, secret })
    }

    /// Serialize the keypair for embedding.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.secret.to_bytes());
        result[32..].copy_from_slice(&self.public.to_bytes());
        result
    }

    /// Create a keypair from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let raw: [u8; 64] = bytes.try_into().ok()?;
        let secret_bytes: [u8; 32] = raw[..32].try_into().ok()?;
        let public_bytes: [u8; 32] = raw[32..].try_into().ok()?;

        let secret = SigningKey::from_bytes(&secret_bytes);
        let public = VerifyingKey::from_bytes(&public_bytes).ok()?;
        Some(Self { public, secret })
    }
}

/// Server keys: public key for verification, secret key for signing.
///
/// Used by the agent to sign SPA knocks and by the client to verify.
#[derive(Debug, Clone)]
pub struct ServerKeys {
    pub public: VerifyingKey,
    pub secret: SigningKey,
}

impl ServerKeys {
    /// Create new server keys from embedded materials.
    pub fn from_embedded() -> Option<Self> {
        TeamKeyPair::from_embedded().map(|pair| Self {
            public: pair.public,
            secret: pair.secret,
        })
    }

    /// Get the public key for verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.secret.verifying_key()
    }
}

impl From<TeamKeyPair> for ServerKeys {
    fn from(pair: TeamKeyPair) -> Self {
        Self {
            public: pair.public,
            secret: pair.secret,
        }
    }
}

/// Parse the embedded team public key, if one was baked in.
pub fn team_pubkey() -> Option<VerifyingKey> {
    TeamKeyPair::from_embedded().map(|pair| pair.public)
}