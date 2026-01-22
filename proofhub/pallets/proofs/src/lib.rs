#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_support::pallet_prelude::*;
use frame_support::{BoundedVec, PalletId};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_io::hashing::blake2_256;
use sp_runtime::transaction_validity::{
	InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
};
use sp_runtime::Perbill;

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct ProofPublicInputs {
	pub merkle_root: [u8; 32],
	pub new_merkle_root: [u8; 32],
	pub input_commitments: Vec<[u8; 32]>,
	pub input_indices: Vec<u32>,
	pub input_paths: Vec<Vec<[u8; 32]>>,
	pub nullifiers: Vec<[u8; 32]>,
	pub new_commitments: Vec<[u8; 32]>,
	pub fee_commitment: [u8; 32],
	pub fee_nullifier: [u8; 32],
	pub tx_id: [u8; 16],
}

pub trait ProofVerify {
	fn verify(proof: &[u8], public_inputs: &[u8]) -> bool;
	fn pedersen_check_u64(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool;
	fn verify_range_proof(
		range_proof: &[u8],
		commitments: &[[u8; 32]],
		public_inputs: &[u8],
		nbits: u32,
	) -> bool;
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::ConstU32;
	use frame_support::traits::{Currency, ExistenceRequirement, FindAuthor};
	use sp_runtime::traits::{Saturating, UniqueSaturatedInto};

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type ProofVerifier: super::ProofVerify;
		type Currency: Currency<Self::AccountId>;
		#[pallet::constant]
		type BaseFee: Get<BalanceOf<Self>>;
		#[pallet::constant]
		type FeePayer: Get<<Self as frame_system::Config>::AccountId>;
		type FindAuthor: FindAuthor<Self::AccountId>;
		#[pallet::constant]
		type MaxProofSize: Get<u32>;
		#[pallet::constant]
		type MaxRangeProofSize: Get<u32>;
		#[pallet::constant]
		type MaxOutputs: Get<u32>;
		#[pallet::constant]
		type GenesisCommitments: Get<&'static [[u8; 32]]>;
		type PoolAccount: Get<<Self as frame_system::Config>::AccountId>;
	}

	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::storage]
	#[pallet::getter(fn nullifier_used)]
	pub type NullifierUsed<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn merkle_root)]
	pub type MerkleRoot<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn current_root)]
	pub type CurrentRoot<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn recent_roots)]
	pub type RecentRoots<T: Config> =
		StorageValue<_, BoundedVec<[u8; 32], ConstU32<64>>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn fee_nullifier_used)]
	pub type FeeNullifierUsed<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn faucet_commitments)]
	pub type FaucetCommitments<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn fee_commitments)]
	pub type FeeCommitments<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn genesis_initialized)]
	pub type GenesisInitialized<T: Config> = StorageValue<_, bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn leaves)]
	pub type Leaves<T: Config> =
		StorageValue<_, BoundedVec<[u8; 32], ConstU32<16384>>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn root_leaf_count)]
	pub type RootLeafCount<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], u32, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn commitment_index)]
	pub type CommitmentIndex<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], u32, OptionQuery>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub _phantom: core::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			MerkleRoot::<T>::put([0u8; 32]);
			CurrentRoot::<T>::put([0u8; 32]);
			RecentRoots::<T>::put(BoundedVec::default());
			Leaves::<T>::put(BoundedVec::default());
			RootLeafCount::<T>::insert([0u8; 32], 0u32);
			for commitment in T::GenesisCommitments::get() {
				FaucetCommitments::<T>::insert(commitment, true);
			}
			GenesisInitialized::<T>::put(true);
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
			for commitment in T::GenesisCommitments::get() {
				if !FaucetCommitments::<T>::contains_key(commitment) {
					FaucetCommitments::<T>::insert(commitment, true);
				}
			}
			if !GenesisInitialized::<T>::get() {
				GenesisInitialized::<T>::put(true);
			}
			Weight::zero()
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		ProofAccepted {
			tx_id: [u8; 16],
			new_merkle_root: [u8; 32],
			outputs: Vec<[u8; 32]>,
			hints_blob: BoundedVec<u8, ConstU32<4096>>,
		},
		ProofRejected,
		FeeDeposited { commitment: [u8; 32] },
		RangeProofVerified,
		FeePaid { author: <T as frame_system::Config>::AccountId, amount: BalanceOf<T> },
		FeePayoutFailed { author: <T as frame_system::Config>::AccountId, amount: BalanceOf<T> },
		DepositAccepted {
			commitment: [u8; 32],
			amount: u64,
			new_merkle_root: [u8; 32],
			hints_blob: BoundedVec<u8, ConstU32<4096>>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		ProofVerificationFailed,
		NullifierAlreadyUsed,
		FeeNullifierAlreadyUsed,
		ProofTooLarge,
		RangeProofTooLarge,
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			match call {
				Call::submit_proof { proof, range_proof, public_inputs, .. } => {
					let max_size = T::MaxProofSize::get() as usize;
					if proof.len() > max_size { return InvalidTransaction::ExhaustsResources.into(); }
					let max_rp = T::MaxRangeProofSize::get() as usize;
					if range_proof.len() > max_rp { return InvalidTransaction::ExhaustsResources.into(); }

					if let Ok(inputs) = ProofPublicInputs::decode(&mut &public_inputs[..]) {
						let anchor = inputs.merkle_root;
						let cur = CurrentRoot::<T>::get();
						if anchor != cur {
							let window = RecentRoots::<T>::get();
							if !window.iter().any(|r| *r == anchor) {
								return InvalidTransaction::Stale.into();
							}
						}
						if inputs.nullifiers.len() != inputs.input_commitments.len() {
							return InvalidTransaction::BadMandatory.into();
						}
						let n = inputs.input_commitments.len();
						if inputs.input_indices.len() != n { return InvalidTransaction::BadMandatory.into(); }
						{
							let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
							for nn in inputs.nullifiers.iter() {
								if *nn == inputs.fee_nullifier { return InvalidTransaction::BadMandatory.into(); }
								if !seen.insert(*nn) { return InvalidTransaction::BadMandatory.into(); }
							}
						}
						if FeeNullifierUsed::<T>::get(inputs.fee_nullifier) {
							return InvalidTransaction::Stale.into();
						}
						for nullifier in inputs.nullifiers.iter() {
							if NullifierUsed::<T>::get(nullifier) { return InvalidTransaction::Stale.into(); }
						}
						ValidTransaction::with_tag_prefix("ProofSubmission")
							.and_provides(inputs.tx_id)
							.and_provides(inputs.fee_nullifier)
							.and_provides(inputs.nullifiers.clone())
							.priority(100)
							.longevity(64)
							.propagate(true)
							.build()
					} else { InvalidTransaction::Call.into() }
				}
				_ => InvalidTransaction::Call.into(),
			}
		}
	}

	impl<T: Config> Pallet<T> {
		fn hash2(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
			let mut data = [0u8; 64];
			data[..32].copy_from_slice(&left);
			data[32..].copy_from_slice(&right);
			blake2_256(&data)
		}
		fn leaf_hash(commitment: [u8; 32]) -> [u8; 32] {
			let mut data = [0u8; 64];
			data[..32].copy_from_slice(&commitment);
			blake2_256(&data)
		}
		fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
			if leaves.is_empty() { return [0u8; 32]; }
			let mut level: alloc::vec::Vec<[u8; 32]> = leaves.to_vec();
			let zero = [0u8; 32];
			while level.len() & (level.len() - 1) != 0 { level.push(zero); }
			let mut cur = level;
			while cur.len() > 1 {
				let mut next = alloc::vec::Vec::with_capacity((cur.len() + 1) / 2);
				for pair in cur.chunks(2) {
					let a = pair[0];
					let b = if pair.len() == 2 { pair[1] } else { zero };
					next.push(Self::hash2(a, b));
				}
				cur = next;
			}
			cur[0]
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(Weight::zero())]
		pub fn deposit_public(
			origin: OriginFor<T>,
			commitment: alloc::vec::Vec<u8>,
			amount: u128,
			blinding: alloc::vec::Vec<u8>,
			hints_blob: BoundedVec<u8, ConstU32<4096>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(commitment.len() == 32 && blinding.len() == 32, Error::<T>::ProofVerificationFailed);
			let mut c_arr = [0u8; 32]; c_arr.copy_from_slice(&commitment[..32]);
			let mut b_arr = [0u8; 32]; b_arr.copy_from_slice(&blinding[..32]);
			let amt_u64: u64 = amount.unique_saturated_into();
			ensure!(T::ProofVerifier::pedersen_check_u64(amt_u64, b_arr, c_arr), Error::<T>::ProofVerificationFailed);
			let pool = T::PoolAccount::get();
			let value: BalanceOf<T> = amount.unique_saturated_into();
			T::Currency::transfer(&who, &pool, value, ExistenceRequirement::KeepAlive)?;
			ensure!(!CommitmentIndex::<T>::contains_key(&c_arr), Error::<T>::ProofVerificationFailed);
			let mut leaves = Leaves::<T>::get();
			let leaf = Self::leaf_hash(c_arr);
			let idx = leaves.len() as u32;
			ensure!(leaves.try_push(leaf).is_ok(), Error::<T>::ProofVerificationFailed);
			CommitmentIndex::<T>::insert(&c_arr, idx);
			let computed_root = Self::compute_merkle_root(&leaves);
			Leaves::<T>::put(leaves);
			let prev = CurrentRoot::<T>::get();
			CurrentRoot::<T>::put(computed_root);
			MerkleRoot::<T>::put(computed_root);
			let leaf_count = Leaves::<T>::get().len() as u32;
			RootLeafCount::<T>::insert(computed_root, leaf_count);
			let mut window = RecentRoots::<T>::get();
			if window.len() >= 64 {
				let mut shifted: BoundedVec<[u8; 32], ConstU32<64>> = BoundedVec::default();
				for i in 1..window.len() { let _ = shifted.try_push(window[i]); }
				window = shifted;
			}
			let _ = window.try_push(prev);
			RecentRoots::<T>::put(&window);
			Self::deposit_event(Event::DepositAccepted { commitment: c_arr, amount: amt_u64, new_merkle_root: computed_root, hints_blob });
			Ok(())
		}

		#[pallet::weight(Weight::zero())]
		pub fn submit_proof(
			origin: OriginFor<T>,
			proof: Vec<u8>,
			range_proof: BoundedVec<u8, <T as Config>::MaxRangeProofSize>,
			public_inputs: Vec<u8>,
			hints_blob: BoundedVec<u8, ConstU32<4096>>,
		) -> DispatchResult {
			ensure_none(origin)?;
			let max_size = T::MaxProofSize::get() as usize;
			ensure!(proof.len() <= max_size, Error::<T>::ProofTooLarge);
			ensure!(range_proof.len() <= T::MaxRangeProofSize::get() as usize, Error::<T>::RangeProofTooLarge);
			let inputs = ProofPublicInputs::decode(&mut &public_inputs[..]).map_err(|_| Error::<T>::ProofVerificationFailed)?;
			ensure!(!FeeNullifierUsed::<T>::get(inputs.fee_nullifier), Error::<T>::FeeNullifierAlreadyUsed);
			let anchor = inputs.merkle_root;
			let current = CurrentRoot::<T>::get();
			if anchor != current {
				let window = RecentRoots::<T>::get();
				ensure!(window.iter().any(|r| *r == anchor), Error::<T>::ProofVerificationFailed);
			}
			{
				let mut cmts: alloc::vec::Vec<[u8; 32]> = inputs.new_commitments.clone();
				ensure!(cmts.len() as u32 <= T::MaxOutputs::get(), Error::<T>::ProofVerificationFailed);
				cmts.push(inputs.fee_commitment);
				let ok = T::ProofVerifier::verify_range_proof(&range_proof, &cmts, &public_inputs, 64);
				ensure!(ok, Error::<T>::ProofVerificationFailed);
				Self::deposit_event(Event::RangeProofVerified);
			}
			let ok = T::ProofVerifier::verify(&proof, &public_inputs);
			if !ok { Self::deposit_event(Event::ProofRejected); Err(Error::<T>::ProofVerificationFailed)?; }
			let anchor_count = RootLeafCount::<T>::get(anchor);
			let mut faucet_commitments_to_consume: Vec<[u8; 32]> = Vec::new();
			for (i, c) in inputs.input_commitments.iter().enumerate() {
				if FaucetCommitments::<T>::contains_key(c) {
					let available = FaucetCommitments::<T>::get(c);
					ensure!(available, Error::<T>::ProofVerificationFailed);
					faucet_commitments_to_consume.push(*c);
					continue;
				}
				if i < inputs.input_paths.len() && !inputs.input_paths[i].is_empty() && i < inputs.input_indices.len() {
					let mut node = Self::leaf_hash(*c);
					let mut idx = inputs.input_indices[i] as usize;
					for sib in inputs.input_paths[i].iter() {
						if (idx & 1) == 0 { node = Self::hash2(node, *sib); } else { node = Self::hash2(*sib, node); }
						idx >>= 1;
					}
					ensure!(node == anchor, Error::<T>::ProofVerificationFailed);
				} else {
					let idx = match CommitmentIndex::<T>::get(c) { Some(v) => v, None => { return Err(Error::<T>::ProofVerificationFailed.into()); } };
					ensure!((idx as u32) < anchor_count, Error::<T>::ProofVerificationFailed);
				}
			}
			for n in inputs.nullifiers.iter() { ensure!(!NullifierUsed::<T>::get(n), Error::<T>::NullifierAlreadyUsed); }
			for n in inputs.nullifiers.iter() { NullifierUsed::<T>::insert(n, true); }
			FeeNullifierUsed::<T>::insert(inputs.fee_nullifier, true);
			for _c in faucet_commitments_to_consume { /* dev faucet: no permanent consume */ }
			{
				let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
				for c in inputs.new_commitments.iter() {
					ensure!(seen.insert(*c), Error::<T>::ProofVerificationFailed);
					ensure!(!CommitmentIndex::<T>::contains_key(c), Error::<T>::ProofVerificationFailed);
				}
			}
			ensure!(FeeCommitments::<T>::get(inputs.fee_commitment), Error::<T>::ProofVerificationFailed);
			FeeCommitments::<T>::insert(inputs.fee_commitment, false);
			ensure!(inputs.new_commitments.len() as u32 <= T::MaxOutputs::get(), Error::<T>::ProofVerificationFailed);
			let mut leaves = Leaves::<T>::get();
			for c in inputs.new_commitments.iter() {
				let leaf = Self::leaf_hash(*c);
				let idx = leaves.len() as u32;
				ensure!(leaves.try_push(leaf).is_ok(), Error::<T>::ProofVerificationFailed);
				CommitmentIndex::<T>::insert(c, idx);
			}
			let computed_root = Self::compute_merkle_root(&leaves);
			Leaves::<T>::put(leaves);
			if inputs.new_merkle_root != [0u8; 32] {
				ensure!(inputs.new_merkle_root == computed_root, Error::<T>::ProofVerificationFailed);
			}
			let prev = CurrentRoot::<T>::get();
			CurrentRoot::<T>::put(computed_root);
			MerkleRoot::<T>::put(computed_root);
			let leaf_count = Leaves::<T>::get().len() as u32;
			RootLeafCount::<T>::insert(computed_root, leaf_count);
			let mut window = RecentRoots::<T>::get();
			if window.len() >= 64 {
				let mut shifted: BoundedVec<[u8; 32], ConstU32<64>> = BoundedVec::default();
				for i in 1..window.len() { let _ = shifted.try_push(window[i]); }
				window = shifted;
			}
			let _ = window.try_push(prev);
			RecentRoots::<T>::put(&window);
			Self::deposit_event(Event::ProofAccepted { tx_id: inputs.tx_id, new_merkle_root: computed_root, outputs: inputs.new_commitments.clone(), hints_blob });

			let payer: <T as frame_system::Config>::AccountId = T::FeePayer::get();
			let amount: BalanceOf<T> = T::BaseFee::get();
			let burn_frac = Perbill::from_percent(50);
			let burn_amount = burn_frac * amount;
			let author_amount = amount.saturating_sub(burn_amount);
			if let Some(author) = T::FindAuthor::find_author(frame_system::Pallet::<T>::digest().logs.iter().filter_map(|d| d.as_pre_runtime())) {
				match T::Currency::transfer(&payer, &author, author_amount, ExistenceRequirement::AllowDeath) {
					Ok(_) => Self::deposit_event(Event::FeePaid { author, amount: author_amount }),
					Err(_) => Self::deposit_event(Event::FeePayoutFailed { author, amount: author_amount }),
				}
			}
			Ok(())
		}

		#[pallet::weight(Weight::zero())]
		pub fn deposit_fee(origin: OriginFor<T>, fee_commitment: [u8; 32]) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let payer: <T as frame_system::Config>::AccountId = T::FeePayer::get();
			let amount: BalanceOf<T> = T::BaseFee::get();
			T::Currency::transfer(&who, &payer, amount, ExistenceRequirement::KeepAlive)?;
			FeeCommitments::<T>::insert(fee_commitment, true);
			Self::deposit_event(Event::FeeDeposited { commitment: fee_commitment });
			Ok(())
		}
	}
}

pub use pallet::*;

pub trait WeightInfo {}

pub mod weights {
	pub struct SubstrateWeight<T>(sp_std::marker::PhantomData<T>);
	impl<T> super::WeightInfo for SubstrateWeight<T> {}
}
