#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use codec::DecodeWithMemTracking;
    use frame_support::traits::BuildGenesisConfig;

    // ── Constants ────────────────────────────────────────────────────────────
    pub const MAX_NAME_LEN: u32 = 64;
    pub const MAX_DESC_LEN: u32 = 256;
    pub const MAX_META_LEN: u32 = 512;
    pub const MAX_DISCLAIMER_LEN: u32 = 1024;
    pub const MAX_INFO_STR_LEN: u32 = 128;

    // ── Types ────────────────────────────────────────────────────────────────

    /// Category of a real-world asset.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, frame_support::Serialize, frame_support::Deserialize)]
    pub enum AssetCategory {
        RealEstate,
        Fleet,
        FinancialInstrument,
        Commodity,
        IntellectualProperty,
    }

    /// Immutable + mutable state for an RWA.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, frame_support::Serialize, frame_support::Deserialize)]
    pub struct RWAAsset<AccountId> {
        pub asset_id: u32,
        pub name: BoundedVec<u8, ConstU32<{ MAX_NAME_LEN }>>,
        pub description: BoundedVec<u8, ConstU32<{ MAX_DESC_LEN }>>,
        pub category: AssetCategory,
        /// USD value in cents (e.g. 890_000_00 = €890 000).
        pub usd_value_cents: u128,
        /// On-chain owner (company admin at genesis; locked while sold).
        pub owner: AccountId,
        /// `true`  → asset physically locked; only a valid note-holder can unlock it.
        /// `false` → asset is freely transferable.
        pub is_locked: bool,
        /// `true` once a `SoldPrivately` or `SoldPublicly` event has been emitted.
        pub is_sold: bool,
        /// Optional freeform metadata blob (JSON-encoded details, images URL, ISIN …)
        pub metadata: BoundedVec<u8, ConstU32<{ MAX_META_LEN }>>,
    }

    /// Company-level information stored once at genesis.
    #[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, frame_support::Serialize, frame_support::Deserialize)]
    pub struct CompanyInfo {
        pub name: BoundedVec<u8, ConstU32<{ MAX_INFO_STR_LEN }>>,
        pub disclaimer: BoundedVec<u8, ConstU32<{ MAX_DISCLAIMER_LEN }>>,
    }

    // ── Pallet ───────────────────────────────────────────────────────────────
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Origin allowed to register/lock assets (typically `EnsureRoot`).
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    // ── Storage ──────────────────────────────────────────────────────────────

    #[pallet::storage]
    pub type Assets<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, RWAAsset<T::AccountId>>;

    #[pallet::storage]
    pub type NextAssetId<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    pub type Company<T: Config> = StorageValue<_, CompanyInfo>;

    // ── Events ───────────────────────────────────────────────────────────────
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AssetRegistered { asset_id: u32, name: BoundedVec<u8, ConstU32<{ MAX_NAME_LEN }>> },
        AssetLocked { asset_id: u32 },
        AssetUnlocked { asset_id: u32 },
        AssetTransferred { asset_id: u32, to: T::AccountId },
        MarkedSold { asset_id: u32 },
    }

    // ── Errors ───────────────────────────────────────────────────────────────
    #[pallet::error]
    pub enum Error<T> {
        AssetNotFound,
        AlreadySold,
        AlreadyLocked,
        NotLocked,
        Unauthorized,
        TooLong,
    }

    // ── Calls ────────────────────────────────────────────────────────────────
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new RWA (Admin only).
        #[pallet::weight(10_000)]
        #[pallet::call_index(0)]
        pub fn register_asset(
            origin: OriginFor<T>,
            owner: T::AccountId,
            name: BoundedVec<u8, ConstU32<{ MAX_NAME_LEN }>>,
            description: BoundedVec<u8, ConstU32<{ MAX_DESC_LEN }>>,
            category: AssetCategory,
            usd_value_cents: u128,
            metadata: BoundedVec<u8, ConstU32<{ MAX_META_LEN }>>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            let asset_id = NextAssetId::<T>::get();
            let asset = RWAAsset {
                asset_id,
                name: name.clone(),
                description,
                category,
                usd_value_cents,
                owner,
                is_locked: false,
                is_sold: false,
                metadata,
            };
            Assets::<T>::insert(asset_id, asset);
            NextAssetId::<T>::put(asset_id.saturating_add(1));
            Self::deposit_event(Event::AssetRegistered { asset_id, name });
            Ok(())
        }

        /// Lock asset for sale (Admin only). Once locked only the note-holder can unlock.
        #[pallet::weight(5_000)]
        #[pallet::call_index(1)]
        pub fn lock_for_sale(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Assets::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let asset = maybe.as_mut().ok_or(Error::<T>::AssetNotFound)?;
                ensure!(!asset.is_locked, Error::<T>::AlreadyLocked);
                asset.is_locked = true;
                Ok(())
            })?;
            Self::deposit_event(Event::AssetLocked { asset_id });
            Ok(())
        }

        /// Internal: called by marketplace to mark as sold.
        /// Uses `EnsureRoot` so only the marketplace (via sudo in tests) can call.
        #[pallet::weight(3_000)]
        #[pallet::call_index(2)]
        pub fn mark_sold(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Assets::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let asset = maybe.as_mut().ok_or(Error::<T>::AssetNotFound)?;
                ensure!(!asset.is_sold, Error::<T>::AlreadySold);
                asset.is_sold = true;
                Ok(())
            })?;
            Self::deposit_event(Event::MarkedSold { asset_id });
            Ok(())
        }

        /// Unlock asset after valid redemption (Admin only after ZK proof verified off-chain).
        #[pallet::weight(5_000)]
        #[pallet::call_index(3)]
        pub fn release_after_redemption(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Assets::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let asset = maybe.as_mut().ok_or(Error::<T>::AssetNotFound)?;
                ensure!(asset.is_locked, Error::<T>::NotLocked);
                asset.is_locked = false;
                Ok(())
            })?;
            Self::deposit_event(Event::AssetUnlocked { asset_id });
            Ok(())
        }

        /// Set company info (Admin only).
        #[pallet::weight(5_000)]
        #[pallet::call_index(4)]
        pub fn set_company_info(
            origin: OriginFor<T>,
            name: BoundedVec<u8, ConstU32<{ MAX_INFO_STR_LEN }>>,
            disclaimer: BoundedVec<u8, ConstU32<{ MAX_DISCLAIMER_LEN }>>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Company::<T>::put(CompanyInfo { name, disclaimer });
            Ok(())
        }
    }

    // ── Genesis Config ────────────────────────────────────────────────────
    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub assets: alloc::vec::Vec<RWAAsset<T::AccountId>>,
        pub company: Option<CompanyInfo>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self { assets: alloc::vec![], company: None }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let mut next_id = 0u32;
            for asset in &self.assets {
                Assets::<T>::insert(next_id, asset.clone());
                next_id = next_id.saturating_add(1);
            }
            NextAssetId::<T>::put(next_id);
            if let Some(info) = &self.company {
                Company::<T>::put(info.clone());
            }
        }
    }

    // ── Internal helpers (used by marketplace pallet) ─────────────────────
    impl<T: Config> Pallet<T> {
        /// Returns true if asset exists and `is_locked = true, is_sold = false`.
        pub fn is_available_for_sale(asset_id: u32) -> bool {
            Assets::<T>::get(asset_id)
                .map(|a| a.is_locked && !a.is_sold)
                .unwrap_or(false)
        }

        /// Mark as sold + stays locked.  Called by marketplace pallet directly.
        pub fn internal_mark_sold(asset_id: u32) -> DispatchResult {
            Assets::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let asset = maybe.as_mut().ok_or(Error::<T>::AssetNotFound)?;
                ensure!(!asset.is_sold, Error::<T>::AlreadySold);
                asset.is_sold = true;
                Ok(())
            })
        }

        /// Unlock asset — called by marketplace after valid redemption.
        pub fn internal_release(asset_id: u32) -> DispatchResult {
            Assets::<T>::try_mutate(asset_id, |maybe| -> Result<(), DispatchError> {
                let asset = maybe.as_mut().ok_or(Error::<T>::AssetNotFound)?;
                asset.is_locked = false;
                Ok(())
            })
        }

        /// Returns `true` if the asset exists and `is_locked = true`.
        /// Used by `pallet-rwa-vault` to guard withdrawals without manual sync.
        pub fn is_locked(asset_id: u32) -> bool {
            Assets::<T>::get(asset_id).map(|a| a.is_locked).unwrap_or(false)
        }
    }
}
