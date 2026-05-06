#![cfg_attr(not(feature = "std"), no_std)]

//! RWA Marketplace pallet.
//!
//! Handles three lifecycle events on the RWA chain:
//! 1. `buy_privately`         — company sells a locked RWA to a note-holder.
//! 2. `redeem_asset`          — note-holder proves spend via nullifier.
//! 3. `xcm_record_purchase`   — called via XCM by the ProofHub sovereign account
//!    after a `purchaseRwa` extrinsic is accepted on the ProofHub parachain.

pub use pallet::*;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use pallet_rwa_registry::pallet as registry;
    use codec::DecodeWithMemTracking;

    pub const MAX_CONTACT_LEN: u32 = 256;

    // ── Sub-types ────────────────────────────────────────────────────────────

    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    pub enum ListingStatus {
        /// Asset is locked and available for private purchase.
        Active,
        /// Sold privately; asset still locked awaiting redemption.
        SoldPrivately,
        /// Sold at full price (public purchase path).
        SoldPublicly,
        /// Listing was cancelled before sale.
        Cancelled,
        /// Redemption complete; asset unlocked.
        Redeemed,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    pub struct Listing<AccountId> {
        /// Company account that created the listing.
        pub seller: AccountId,
        /// On-chain asset identifier (from pallet-rwa-registry).
        pub asset_id: u32,
        /// Asking price denominated in ProofHub commitment value (informational only).
        /// Payment is proven via ZK on ProofHub — no direct transfer on this chain.
        pub price_hint: u128,
        /// Current lifecycle state.
        pub status: ListingStatus,
        /// Blake2-256 hash of the ProofHub output commitment used as payment.
        /// Set by the buyer when calling buy_privately.
        /// `None` until `buy_privately` is called.
        pub entry_commitment_hash: Option<[u8; 32]>,
    }

    /// Redemption record stored when a note-holder presents a spend proof.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    pub struct RedemptionClaim<AccountId> {
        pub asset_id: u32,
        /// ProofHub nullifier hash — unique per note; prevents double redemption.
        pub nullifier_hash: [u8; 32],
        /// Optional contact info supplied by the redeemer (encrypted off-chain).
        pub contact: Option<BoundedVec<u8, ConstU32<{ MAX_CONTACT_LEN }>>>,
        pub redeemer: AccountId,
    }

    // ── Config ───────────────────────────────────────────────────────────────
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config:
        frame_system::Config + registry::Config
    {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        // AdminOrigin is inherited from registry::Config — no duplicate needed.
        // Payment for private purchases is proven via ZK on ProofHub — no direct
        // token transfer occurs in buy_privately.

        /// AccountId of the ProofHub sovereign account on this chain.
        /// Derived from `Sibling(ProofHub para id)`.
        /// Only this account is allowed to call `xcm_record_purchase`.
        #[pallet::constant]
        type ProofHubSovereign: Get<Self::AccountId>;
    }

    /// A purchase initiated from the ProofHub parachain via XCM.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    pub struct ProofHubPurchaseRecord {
        /// First 4 bytes of ProofHub's `rwa_id` (LE u32 asset_id), rest zero.
        pub rwa_id:               [u8; 32],
        /// 32-byte AccountId of the buyer on this chain (from `destination`).
        pub buyer:                [u8; 32],
        /// Phase 6: spend_tag = BLAKE3("nulla_spend_tag_v1" || deposit_pk_bytes).
        /// Unlinkable from the original deposit commitment.
        pub spend_tag:            [u8; 32],
        /// Nullifier — proves the note was spent exactly once.
        pub nullifier:            [u8; 32],
        /// Private ownership note: BLAKE3("nulla_rwa_ownership_v1" || rwa_id || blinding).
        /// The buyer reveals `blinding` to `redeem_rwa_ownership` to prove ownership.
        pub ownership_commitment: [u8; 32],
    }

    // ── Storage ──────────────────────────────────────────────────────────────

    /// Active / historical listings keyed by asset_id.
    #[pallet::storage]
    pub type Listings<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u32,
        Listing<T::AccountId>,
    >;

    /// Redemption claims keyed by nullifier_hash.
    #[pallet::storage]
    pub type RedemptionClaims<T: Config> =
        StorageMap<_, Identity, [u8; 32], RedemptionClaim<T::AccountId>>;

    /// Guard against nullifier reuse on THIS chain.
    #[pallet::storage]
    pub type NullifierUsed<T: Config> = StorageMap<_, Identity, [u8; 32], bool, ValueQuery>;

    /// Purchase records received from ProofHub via XCM, keyed by tx_id.
    #[pallet::storage]
    pub type ProofHubPurchases<T: Config> =
        StorageMap<_, Identity, [u8; 16], ProofHubPurchaseRecord>;

    /// Guards against double-redemption of ownership notes, keyed by tx_id.
    #[pallet::storage]
    pub type OwnershipRedeemed<T: Config> =
        StorageMap<_, Identity, [u8; 16], bool, ValueQuery>;

    // ── Events ───────────────────────────────────────────────────────────────
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Asset listed for private sale.
        AssetListed {
            asset_id: u32,
            seller: T::AccountId,
            price_hint: u128,
        },
        /// Listing cancelled (before any sale).
        ListingCancelled { asset_id: u32 },
        /// Private sale recorded.  Entry commitment hash stored on-chain.
        AssetSoldPrivately {
            asset_id: u32,
            buyer: T::AccountId,
            entry_commitment_hash: [u8; 32],
        },
        /// Redemption claim submitted on-chain.
        RedemptionSubmitted {
            asset_id: u32,
            nullifier_hash: [u8; 32],
            redeemer: T::AccountId,
        },
        /// Asset fully redeemed; company should physically release it.
        AssetRedeemed { asset_id: u32, nullifier_hash: [u8; 32] },
        /// ProofHub XCM purchase received and recorded.
        ProofHubPurchaseReceived {
            tx_id:                [u8; 16],
            asset_id:             u32,
            buyer:                [u8; 32],
            /// Phase 6: spend_tag (unlinkable from deposit commitment).
            spend_tag:            [u8; 32],
            nullifier:            [u8; 32],
            ownership_commitment: [u8; 32],
        },
        /// Ownership note redeemed — company should release the physical asset.
        OwnershipRedeemed {
            tx_id:    [u8; 16],
            asset_id: u32,
            redeemer: T::AccountId,
        },
    }

    // ── Errors ───────────────────────────────────────────────────────────────
    #[pallet::error]
    pub enum Error<T> {
        ListingNotFound,
        NotSeller,
        NotActive,
        AlreadySold,
        AssetNotAvailableForSale,
        NullifierAlreadyUsed,
        AssetNotSoldPrivately,
        /// Caller is not the ProofHub sovereign account.
        NotProofHubSovereign,
        /// A purchase with this tx_id was already recorded.
        PurchaseAlreadyRecorded,
        /// No purchase record found for the given tx_id.
        PurchaseNotFound,
        /// Ownership note for this tx_id was already redeemed.
        OwnershipAlreadyRedeemed,
        /// The supplied blinding does not match the stored ownership commitment.
        InvalidOwnershipProof,
    }

    // ── Calls ────────────────────────────────────────────────────────────────
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new listing for a locked asset (Admin only).
        ///
        /// `seller` is the company account that receives off-chain settlement.
        /// `price_hint` is informational — the actual payment is proven via ZK
        /// on ProofHub and is not enforced by this chain.
        #[pallet::weight(10_000)]
        #[pallet::call_index(0)]
        pub fn list_asset(
            origin: OriginFor<T>,
            asset_id: u32,
            seller: T::AccountId,
            price_hint: u128,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            ensure!(
                registry::Pallet::<T>::is_available_for_sale(asset_id),
                Error::<T>::AssetNotAvailableForSale
            );
            let listing = Listing {
                seller: seller.clone(),
                asset_id,
                price_hint,
                status: ListingStatus::Active,
                entry_commitment_hash: None,
            };
            Listings::<T>::insert(asset_id, listing);
            Self::deposit_event(Event::AssetListed { asset_id, seller, price_hint });
            Ok(())
        }

        /// Cancel an active listing (Admin only).
        ///
        /// Also releases the registry lock so the asset can be re-listed or
        /// disposed of — without this the asset would stay permanently locked.
        #[pallet::weight(5_000)]
        #[pallet::call_index(1)]
        pub fn cancel_listing(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Listings::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let listing = maybe.as_mut().ok_or(Error::<T>::ListingNotFound)?;
                ensure!(listing.status == ListingStatus::Active, Error::<T>::NotActive);
                listing.status = ListingStatus::Cancelled;
                Ok(())
            })?;
            // Release the registry lock so the asset is no longer permanently stuck.
            registry::Pallet::<T>::internal_release(asset_id)?;
            Self::deposit_event(Event::ListingCancelled { asset_id });
            Ok(())
        }

        /// Private purchase via ZK proof.
        ///
        /// The buyer has already spent an existing ProofHub note on the ProofHub
        /// parachain via `submit_proof`, producing an output commitment C of value
        /// >= listing.price_hint.  The buyer passes `entry_commitment_hash =
        /// blake2_256(C)` here.  No token transfer occurs on this chain — the
        /// payment is proven entirely on ProofHub.
        ///
        /// The seller verifies off-chain that:
        ///   1. A `ProofAccepted` event on ProofHub contains C as an output.
        ///   2. The committed value >= listing.price_hint.
        ///   3. The seller can redeem C on ProofHub using the blinding provided
        ///      off-chain by the protocol.
        #[pallet::weight(15_000)]
        #[pallet::call_index(2)]
        pub fn buy_privately(
            origin: OriginFor<T>,
            asset_id: u32,
            entry_commitment_hash: [u8; 32],
        ) -> DispatchResult {
            let buyer = ensure_signed(origin)?;
            Listings::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let listing = maybe.as_mut().ok_or(Error::<T>::ListingNotFound)?;
                ensure!(listing.status == ListingStatus::Active, Error::<T>::NotActive);
                ensure!(
                    registry::Pallet::<T>::is_available_for_sale(asset_id),
                    Error::<T>::AssetNotAvailableForSale
                );
                // No token transfer — payment is proven via ZK on ProofHub.
                listing.status = ListingStatus::SoldPrivately;
                listing.entry_commitment_hash = Some(entry_commitment_hash);
                // Mark registry as sold (asset stays locked until redemption).
                registry::Pallet::<T>::internal_mark_sold(asset_id)?;
                Ok(())
            })?;
            Self::deposit_event(Event::AssetSoldPrivately {
                asset_id,
                buyer,
                entry_commitment_hash,
            });
            Ok(())
        }

        /// Redeem an asset by presenting the ProofHub spend nullifier.
        ///
        /// The caller asserts that they have spent the private note on ProofHub
        /// (i.e. `submit_proof` succeeded and `nullifier_hash` is in ProofHub's
        /// `NullifierUsed` storage).  The company verifies this off-chain before
        /// physically handing over the asset.  The `AssetRedeemed` event is the
        /// on-chain anchor for that handover.
        #[pallet::weight(15_000)]
        #[pallet::call_index(3)]
        pub fn redeem_asset(
            origin: OriginFor<T>,
            asset_id: u32,
            nullifier_hash: [u8; 32],
            contact: Option<BoundedVec<u8, ConstU32<{ MAX_CONTACT_LEN }>>>,
        ) -> DispatchResult {
            let redeemer = ensure_signed(origin)?;
            // Guard against double-redemption on this chain.
            ensure!(
                !NullifierUsed::<T>::get(nullifier_hash),
                Error::<T>::NullifierAlreadyUsed
            );
            // Asset must have been sold privately first.
            let listing =
                Listings::<T>::get(asset_id).ok_or(Error::<T>::ListingNotFound)?;
            ensure!(
                listing.status == ListingStatus::SoldPrivately,
                Error::<T>::AssetNotSoldPrivately
            );

            // Mark nullifier used.
            NullifierUsed::<T>::insert(nullifier_hash, true);

            // Store redemption claim.
            let claim = RedemptionClaim {
                asset_id,
                nullifier_hash,
                contact,
                redeemer: redeemer.clone(),
            };
            RedemptionClaims::<T>::insert(nullifier_hash, claim);

            // Update listing status.
            Listings::<T>::mutate(asset_id, |maybe| {
                if let Some(l) = maybe.as_mut() {
                    l.status = ListingStatus::Redeemed;
                }
            });

            // Unlock in registry — company can now dispose of physical asset.
            registry::Pallet::<T>::internal_release(asset_id)?;

            Self::deposit_event(Event::RedemptionSubmitted {
                asset_id,
                nullifier_hash,
                redeemer,
            });
            Self::deposit_event(Event::AssetRedeemed { asset_id, nullifier_hash });
            Ok(())
        }

        /// Record a purchase originating from the ProofHub parachain.
        ///
        /// This extrinsic MUST only be called via XCM `Transact` by the ProofHub
        /// sovereign account (`Sibling(2000)` as a `Signed` origin).  Any other
        /// caller is rejected with `NotProofHubSovereign`.
        ///
        /// The pallet stores a `ProofHubPurchaseRecord` keyed by `tx_id`, guards
        /// against double-recording (same `tx_id`), and emits
        /// `ProofHubPurchaseReceived`.  The company SHOULD watch for this event and
        /// initiate the off-chain redemption flow for the buyer.
        #[pallet::weight(10_000)]
        #[pallet::call_index(4)]
        pub fn xcm_record_purchase(
            origin: OriginFor<T>,
            asset_id: u32,
            buyer: [u8; 32],
            // Phase 6: spend_tag (was commitment) — same [u8;32] type, same SCALE position.
            spend_tag: [u8; 32],
            nullifier: [u8; 32],
            tx_id: [u8; 16],
            ownership_commitment: [u8; 32],
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            ensure!(caller == T::ProofHubSovereign::get(), Error::<T>::NotProofHubSovereign);
            ensure!(
                !ProofHubPurchases::<T>::contains_key(tx_id),
                Error::<T>::PurchaseAlreadyRecorded
            );

            // Build rwa_id: first 4 bytes = asset_id as LE u32, rest zero.
            let mut rwa_id = [0u8; 32];
            rwa_id[..4].copy_from_slice(&asset_id.to_le_bytes());

            let record = ProofHubPurchaseRecord { rwa_id, buyer, spend_tag, nullifier, ownership_commitment };
            ProofHubPurchases::<T>::insert(tx_id, record);

            Self::deposit_event(Event::ProofHubPurchaseReceived {
                tx_id,
                asset_id,
                buyer,
                spend_tag,
                nullifier,
                ownership_commitment,
            });
            Ok(())
        }

        /// Redeem an RWA ownership note.
        ///
        /// The caller proves they hold the private ownership note by revealing the
        /// `blinding` used to compute `ownership_commitment` at purchase time.
        /// The chain verifies:
        ///   BLAKE3("nulla_rwa_ownership_v1" || rwa_id || blinding) == record.ownership_commitment
        ///
        /// On success an `OwnershipRedeemed` event is emitted — the company watches
        /// for this event and releases the physical asset to the redeemer.
        /// This is a PUBLIC transaction: the redeemer's identity and the asset_id
        /// are visible on-chain.  The link between the original buyer and the
        /// redeemer is broken only if they are different accounts.
        #[pallet::weight(10_000)]
        #[pallet::call_index(5)]
        pub fn redeem_rwa_ownership(
            origin: OriginFor<T>,
            tx_id: [u8; 16],
            blinding: [u8; 32],
        ) -> DispatchResult {
            let redeemer = ensure_signed(origin)?;

            let record = ProofHubPurchases::<T>::get(tx_id)
                .ok_or(Error::<T>::PurchaseNotFound)?;

            ensure!(
                !OwnershipRedeemed::<T>::get(tx_id),
                Error::<T>::OwnershipAlreadyRedeemed
            );

            // Verify the ownership commitment: BLAKE3(domain || rwa_id || blinding)
            let expected = Self::compute_ownership_commitment(record.rwa_id, blinding);
            ensure!(expected == record.ownership_commitment, Error::<T>::InvalidOwnershipProof);

            OwnershipRedeemed::<T>::insert(tx_id, true);

            let asset_id = u32::from_le_bytes([
                record.rwa_id[0], record.rwa_id[1], record.rwa_id[2], record.rwa_id[3],
            ]);
            Self::deposit_event(Event::OwnershipRedeemed { tx_id, asset_id, redeemer });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// BLAKE3("nulla_rwa_ownership_v1" || rwa_id || blinding)
        fn compute_ownership_commitment(rwa_id: [u8; 32], blinding: [u8; 32]) -> [u8; 32] {
            use blake3::Hasher;
            let mut h = Hasher::new();
            h.update(b"nulla_rwa_ownership_v1");
            h.update(&rwa_id);
            h.update(&blinding);
            *h.finalize().as_bytes()
        }
    }
}
