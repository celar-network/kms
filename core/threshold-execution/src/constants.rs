use const_format::concatcp;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        /// log_2 of parameter B_{SwitchSquash}, always using the upper bound
        pub(crate) const LOG_B_SWITCH_SQUASH: u32 = 70;
        pub (crate) const B_SWITCH_SQUASH: u128 = 1 << LOG_B_SWITCH_SQUASH;

        /// Maximum number of PRSS party sets (n choose t).
        ///
        /// ⚠️ CORRECTNESS BOUND, not a cost limit. The reconstructed PRSS
        /// flooding mask is bounded by binom(n,t) · 2^(LOG_B_SWITCH_SQUASH +
        /// STATSEC + 1); decryption rounds at Δ = 2^123 (u128 modulus, 4-bit
        /// message+carry, padding bit), so correctness requires the mask plus
        /// the real post-squash noise (≤ 2^LOG_B_SWITCH_SQUASH) to stay under
        /// Δ/2 = 2^122. At STATSEC = 40 that means binom(n,t) < 2^11 — this
        /// constant is exactly that bound, with the real noise absorbed by the
        /// slack between 2047 and 2048. Raising it past 2047 produces silently
        /// wrong plaintexts, not an error.
        pub(crate) const PRSS_SIZE_MAX: usize = 2047;

        /// Statistical security parameter in bits — **PRSS path**.
        ///
        /// 40 is this path's CEILING at PRSS_SIZE_MAX (see above), not a free
        /// choice. Do not raise without shrinking the permitted set count.
        pub const STATSEC: u32 = 40;

        /// Statistical security parameter in bits — **TUniform path**
        /// (large-session offline / `fill_from_bits_preproc` family).
        ///
        /// This path's mask carries NO binom(n,t) factor — it is bounded by
        /// 2^(LOG_B_SWITCH_SQUASH + STATSEC_TUNIFORM + 1) — so its ceiling is
        /// 50: 2^121 (mask) + 2^70 (real noise) < 2^122 (Δ/2), with 2×
        /// headroom. 51 fails on the additive real-noise term.
        ///
        /// [Celar fork of c6b0fdd3: split from the global STATSEC so the
        /// large-session path can use its headroom; upstream issue proposes
        /// making this configurable properly.]
        pub const STATSEC_TUNIFORM: u32 = 50;

        // Compile-time ceiling checks — exceeding either bound corrupts
        // plaintexts SILENTLY (from_expanded_msg rounds into a different
        // block value; nothing errors until an unrelated PRF bound at 57).
        const _: () = assert!(
            LOG_B_SWITCH_SQUASH + STATSEC_TUNIFORM + 1 < 122,
            "TUniform flooding mask exceeds the decryption margin: \
             2^(70 + STATSEC_TUNIFORM + 1) plus real noise must stay under Delta/2 = 2^122"
        );
        const _: () = assert!(
            // 11 = ceil(log2(PRSS_SIZE_MAX + 1)); equality is permitted only
            // because binom <= 2047 < 2048 leaves the slack that absorbs the
            // real-noise term.
            LOG_B_SWITCH_SQUASH + STATSEC + 1 + 11 <= 122,
            "PRSS flooding mask exceeds the decryption margin at PRSS_SIZE_MAX"
        );

        /// constants for key separation in PRSS/PRZS
        pub(crate) const PHI_XOR_CONSTANT: u8 = 2;
        pub(crate) const CHI_XOR_CONSTANT: u8 = 1;

        // ---- MPC tuning knobs ----
        //
        // Each value is configurable at runtime via an environment variable and
        // read once on first access (`LazyLock`). When the variable is unset or
        // cannot be parsed as a `usize`, the documented default is used.

        /// Reads a `usize` tuning value from environment variable `name`, falling
        /// back to `default` when unset or unparseable.
        fn env_usize(name: &str, default: usize) -> usize {
            let value = match std::env::var(name) {
                Ok(raw) => {
                    raw.trim().parse::<usize>().unwrap_or_else(|_| {
                        tracing::warn!(
                            "Invalid usize value {raw:?} for env var {name}; using default {default}"
                        );
                        default
                    })
                },
                Err(e) => {
                    tracing::warn!("Error reading env var {name}: {e:?}; using default {default}");
                    default
                },
            };
            tracing::info!("Using tuning value {value} from env var {name} ");
            value
        }

        /// Amount of triples generated in one batch by the orchestrator.
        /// Env: `MPC_DKG_BATCH_SIZE_TRIPLES` (default 10000).
        pub(crate) static BATCH_SIZE_TRIPLES: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_BATCH_SIZE_TRIPLES", 10000));
        /// Amount of bits generated in one batch by the orchestrator.
        /// Env: `MPC_DKG_BATCH_SIZE_BITS` (default 10000).
        pub(crate) static BATCH_SIZE_BITS: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_BATCH_SIZE_BITS", 10000));
        /// Number of batches that can be queued per producer thread in the
        /// orchestrator. A value of 2 enables double-buffering: a producer can
        /// prepare the next batch while the consumer drains the current one.
        /// Env: `MPC_DKG_CHANNEL_BUFFER_SIZE` (default 2).
        pub(crate) static CHANNEL_BUFFER_SIZE: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_CHANNEL_BUFFER_SIZE", 2));
        /// Progress tracker reports every `TRACKER_LOG_PERCENTAGE` percent.
        /// Env: `MPC_DKG_TRACKER_LOG_PERCENTAGE` (default 5).
        pub static TRACKER_LOG_PERCENTAGE: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_TRACKER_LOG_PERCENTAGE", 5));

        // ---- Minimum rayon chunk sizes (minimum items per parallel task) ----
        // Tuning knobs for the parallel preprocessing loops: large enough to
        // amortize rayon's split/join overhead and to avoid oversubscription
        // under the orchestrator's session-level parallelism, small enough to
        // still parallelize some tasks.
        // NOTE: These are starting points and should be benchmarked and adjusted as needed.

        /// TUniform noise assembly: very cheap per item (~`bound + 2` ring ops).
        /// Env: `MPC_DKG_TUNIFORM_PAR_MIN_CHUNK` (default 4096).
        pub(crate) static TUNIFORM_GEN_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_TUNIFORM_PAR_MIN_CHUNK", 4096));
        /// PRSS / PRZS / mask batch generation: a few AES-PRF evaluations per item.
        /// Env: `MPC_PRSS_PAR_MIN_CHUNK` (default 1024).
        pub(crate) static PRSS_GEN_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_PRSS_PAR_MIN_CHUNK", 1024));
        /// d-value reconstruction in triple/square generation (nsmall offline) : heavy per item
        /// (a Shamir reconstruction).
        /// Env: `MPC_D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK` (default 256).
        pub(crate) static D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                env_usize("MPC_D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK", 256)
            });
        /// Robust-open reconstruction (`sharing::open`).
        /// Env: `MPC_ROBUST_OPEN_PAR_MIN_CHUNK` (default 256).
        pub(crate) static ROBUST_OPEN_RECONSTRUCTION_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                env_usize("MPC_ROBUST_OPEN_PAR_MIN_CHUNK", 256)
            });
    }
}

/// keygen directories (anchored to the workspace root so paths are stable
/// regardless of which crate's tests are running or what the CWD is).
/// threshold-execution lives at `core/threshold-execution/`, so `/../..` reaches the workspace root.
pub const TEMP_DIR: &str = concatcp!(env!("CARGO_MANIFEST_DIR"), "/../../temp");

pub const SMALL_TEST_KEY_PATH: &str = concatcp!(TEMP_DIR, "/small_test_keys.bin");
pub const REAL_KEY_PATH: &str = concatcp!(TEMP_DIR, "/default_keys.bin");
