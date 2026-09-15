#![cfg_attr(not(feature = "std"), no_std)]

//! AuthGate access-key pallet.
//!
//! Handles the access-key lifecycle on the AuthGate parachain:
//! 1. `list_access_slot`      — admin registers a Web2 app with its price and payment account.
//! 2. `xcm_record_access_grant` — called via XCM by the ProofHub sovereign account
//!    after a `purchase_access` extrinsic is accepted on the ProofHub chain.
//! 3. `use_access_key`        — user proves ownership of blinding and consumes the key
//!    (single-use). Emits `AccessKeyUsed` which the Web2 app watches for login.

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use codec::DecodeWithMemTracking;

    pub const MAX_APP_NAME_LEN: u32 = 256;

    // ── Sub-types ────────────────────────────────────────────────────────────

    /// Metadata for a registered Web2 application.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    pub struct AppSlot {
        /// Human-readable app name (informational only).
        pub name: BoundedVec<u8, ConstU32<{ MAX_APP_NAME_LEN }>>,
        /// Access price in planck. Checked against `AccessKeyPrices` on ProofHub.
        pub price: u64,
        /// ProofHub account that receives payment when a note is spent.
        /// This is an AccountId on the **ProofHub** chain, stored here for reference.
        pub payment_account: [u8; 32],
        /// Whether this slot is accepting new purchases.
        pub active: bool,
    }

    /// A grant record received from ProofHub via XCM.
    /// Mirrors `ProofHubPurchaseRecord` in rwa-marketplace but scoped to access keys.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    pub struct AccessGrant {
        /// The app this grant is for.
        pub app_id: [u8; 32],
        /// Nullifier — proves the note was spent exactly once on ProofHub.
        pub nullifier: [u8; 32],
        /// BLAKE3("nulla_access_key_v1" || app_id || blinding).
        /// The user reveals `blinding` to `use_access_key` to prove ownership.
        pub access_key_commitment: [u8; 32],
        /// Whether this key has been consumed by `use_access_key`.
        pub used: bool,
    }

    // ── Config ───────────────────────────────────────────────────────────────

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Origin allowed to register apps and set prices (sudo/root in production).
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// AccountId of the ProofHub sovereign account on this chain (Sibling(2000)).
        #[pallet::constant]
        type ProofHubSovereign: Get<Self::AccountId>;

        /// AccountId of the secondary ProofHub sovereign (Sibling(2002)).
        #[pallet::constant]
        type ProofHubSovereign2: Get<Self::AccountId>;
    }

    // ── Storage ──────────────────────────────────────────────────────────────

    /// Registry of Web2 apps, keyed by app_id ([u8;32]).
    #[pallet::storage]
    pub type AppRegistry<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], AppSlot>;

    /// Access grants received from ProofHub via XCM, keyed by tx_id.
    #[pallet::storage]
    pub type AccessGrants<T: Config> =
        StorageMap<_, Identity, [u8; 16], AccessGrant>;

    /// Guard against double-use: once `use_access_key` succeeds the tx_id is here.
    /// (Also stored as `used: true` in AccessGrant, but this map enables fast lookup.)
    #[pallet::storage]
    pub type KeyUsed<T: Config> =
        StorageMap<_, Identity, [u8; 16], bool, ValueQuery>;

    // ── Events ───────────────────────────────────────────────────────────────

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new Web2 app slot was registered.
        AppSlotRegistered {
            app_id: [u8; 32],
            price: u64,
        },
        /// An app slot was updated (price, active status, etc.).
        AppSlotUpdated { app_id: [u8; 32] },
        /// A ProofHub XCM access grant was received and recorded.
        AccessGrantReceived {
            tx_id: [u8; 16],
            app_id: [u8; 32],
            nullifier: [u8; 32],
            /// The commitment — not the secret blinding; safe to emit.
            access_key_commitment: [u8; 32],
        },
        /// Access key consumed — the Web2 app should open a session for the presenter.
        /// Emitted when the user reveals blinding and it matches the commitment.
        AccessKeyUsed {
            tx_id: [u8; 16],
            app_id: [u8; 32],
        },
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    #[pallet::error]
    pub enum Error<T> {
        /// No app registered for this app_id.
        AppNotFound,
        /// App slot is not accepting purchases.
        AppNotActive,
        /// Caller is not the ProofHub sovereign account.
        NotProofHubSovereign,
        /// A grant with this tx_id was already recorded.
        GrantAlreadyRecorded,
        /// No grant found for the given tx_id.
        GrantNotFound,
        /// This key has already been used.
        KeyAlreadyUsed,
        /// The supplied blinding does not match the stored commitment.
        InvalidBlinding,
        /// The grant's app_id does not match the registered app.
        AppIdMismatch,
    }

    // ── Calls ────────────────────────────────────────────────────────────────

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn validate_unsigned(
            _source: TransactionSource,
            _call: &Self::Call,
        ) -> TransactionValidity {
            InvalidTransaction::Call.into()
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new Web2 app slot (admin only).
        ///
        /// `app_id`          — 32-byte unique identifier chosen by the app operator.
        /// `name`            — human-readable label (stored for reference).
        /// `price`           — cost in planck; must match `AccessKeyPrices` on ProofHub.
        /// `payment_account` — ProofHub AccountId (raw bytes) that receives payment.
        #[pallet::weight(10_000)]
        #[pallet::call_index(0)]
        pub fn list_access_slot(
            origin: OriginFor<T>,
            app_id: [u8; 32],
            name: BoundedVec<u8, ConstU32<{ MAX_APP_NAME_LEN }>>,
            price: u64,
            payment_account: [u8; 32],
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            let slot: AppSlot = AppSlot { name, price, payment_account, active: true };
            AppRegistry::<T>::insert(app_id, slot);
            Self::deposit_event(Event::AppSlotRegistered { app_id, price });
            Ok(())
        }

        /// Update an existing app slot (admin only).
        ///
        /// Can change price, payment_account, active flag, or name.
        #[pallet::weight(5_000)]
        #[pallet::call_index(1)]
        pub fn update_access_slot(
            origin: OriginFor<T>,
            app_id: [u8; 32],
            name: Option<BoundedVec<u8, ConstU32<{ MAX_APP_NAME_LEN }>>>,
            price: Option<u64>,
            payment_account: Option<[u8; 32]>,
            active: Option<bool>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            AppRegistry::<T>::try_mutate(app_id, |maybe| -> Result<(), DispatchError> {
                let slot = maybe.as_mut().ok_or(Error::<T>::AppNotFound)?;
                if let Some(n) = name { slot.name = n; }
                if let Some(p) = price { slot.price = p; }
                if let Some(pa) = payment_account { slot.payment_account = pa; }
                if let Some(a) = active { slot.active = a; }
                Ok(())
            })?;
            Self::deposit_event(Event::AppSlotUpdated { app_id });
            Ok(())
        }

        /// Record an access grant originating from the ProofHub parachain via XCM.
        ///
        /// MUST only be called via XCM `Transact` by the ProofHub sovereign account.
        /// Any other caller is rejected with `NotProofHubSovereign`.
        #[pallet::weight(10_000)]
        #[pallet::call_index(2)]
        pub fn xcm_record_access_grant(
            origin: OriginFor<T>,
            app_id: [u8; 32],
            nullifier: [u8; 32],
            tx_id: [u8; 16],
            access_key_commitment: [u8; 32],
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            ensure!(
                caller == T::ProofHubSovereign::get()
                    || caller == T::ProofHubSovereign2::get(),
                Error::<T>::NotProofHubSovereign
            );
            let slot = AppRegistry::<T>::get(app_id).ok_or(Error::<T>::AppNotFound)?;
            ensure!(slot.active, Error::<T>::AppNotActive);
            ensure!(
                !AccessGrants::<T>::contains_key(tx_id),
                Error::<T>::GrantAlreadyRecorded
            );

            let grant = AccessGrant { app_id, nullifier, access_key_commitment, used: false };
            AccessGrants::<T>::insert(tx_id, grant);

            Self::deposit_event(Event::AccessGrantReceived {
                tx_id,
                app_id,
                nullifier,
                access_key_commitment,
            });
            Ok(())
        }

        /// Consume an access key — single use.
        ///
        /// The caller proves they hold the private blinding used at purchase time by
        /// revealing it here.  The chain verifies:
        ///   BLAKE3("nulla_access_key_v1" || app_id || blinding) == grant.access_key_commitment
        ///
        /// On success the grant is marked `used = true` and `AccessKeyUsed` is emitted.
        /// The Web2 app watches for this event (or queries the storage) to open a session.
        ///
        /// This is a SIGNED transaction; the caller's identity becomes visible on-chain
        /// at this point.  The link between the original note-spender and the login
        /// account is broken only if they are different.
        #[pallet::weight(10_000)]
        #[pallet::call_index(3)]
        pub fn use_access_key(
            origin: OriginFor<T>,
            tx_id: [u8; 16],
            blinding: [u8; 32],
        ) -> DispatchResult {
            let _caller = ensure_signed(origin)?;

            ensure!(!KeyUsed::<T>::get(tx_id), Error::<T>::KeyAlreadyUsed);

            let mut grant = AccessGrants::<T>::get(tx_id)
                .ok_or(Error::<T>::GrantNotFound)?;

            ensure!(!grant.used, Error::<T>::KeyAlreadyUsed);

            let expected = Self::compute_access_key_commitment(grant.app_id, blinding);
            ensure!(expected == grant.access_key_commitment, Error::<T>::InvalidBlinding);

            grant.used = true;
            AccessGrants::<T>::insert(tx_id, &grant);
            KeyUsed::<T>::insert(tx_id, true);

            Self::deposit_event(Event::AccessKeyUsed { tx_id, app_id: grant.app_id });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// BLAKE3("nulla_access_key_v1" || app_id || blinding)
        pub fn compute_access_key_commitment(app_id: [u8; 32], blinding: [u8; 32]) -> [u8; 32] {
            use blake3::Hasher;
            let mut h = Hasher::new();
            h.update(b"nulla_access_key_v1");
            h.update(&app_id);
            h.update(&blinding);
            *h.finalize().as_bytes()
        }
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
