#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_support::pallet_prelude::*;
use frame_support::BoundedVec;
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_io::hashing::blake2_256;
use sp_runtime::transaction_validity::{
	InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
};

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct ProofPublicInputs {
	pub merkle_root: [u8; 32],
	pub new_merkle_root: [u8; 32],
	pub input_commitments: Vec<[u8; 32]>,
	pub input_indices: Vec<u32>,
	pub input_paths: Vec<Vec<[u8; 32]>>,
	pub nullifiers: Vec<[u8; 32]>,
	pub new_commitments: Vec<[u8; 32]>,
	pub tx_id: [u8; 16],
}

pub trait ProofVerify {
	fn verify(proof: &[u8], public_inputs: &[u8]) -> bool;
	fn verify_commitment(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool;
	fn verify_opening_knowledge(
		value: u64,
		commitment: [u8; 32],
		proof: &[u8],
		binding: &[u8],
	) -> bool;
	fn verify_range_proof(
		range_proof: &[u8],
		commitments: &[[u8; 32]],
		public_inputs: &[u8],
		nbits: u32,
	) -> bool;
	/// Ristretto point subtraction: returns compressed(C_a - C_b), or None if
	/// either point is not a valid compressed Ristretto point.
	fn pedersen_subtract(c_a: &[u8; 32], c_b: &[u8; 32]) -> Option<[u8; 32]>;

	// --- Phase 10 (Lelantus / Groth–Kohlweiss one-of-many) ---

	/// Verify a one-of-many spend proof: ∃ unspecified coin i in `coins` with
	/// C_i − serial·G1 − price·G − change = r·H known to the prover.
	/// `change` = [0u8;32] (identity) when no change output.
	fn verify_one_of_many(
		proof: &[u8],
		coins: &[[u8; 32]],
		serial: &[u8; 32],
		price: u64,
		change: &[u8; 32],
		context: &[u8],
	) -> bool;
	/// Verify a deposit coin opening: coin − amount·G = s·G1 + r·H (96-byte proof).
	fn verify_deposit_open(coin: &[u8; 32], amount: u64, proof: &[u8], context: &[u8]) -> bool;
	/// Verify new_coin − change = s'·G1 PoK (64-byte proof) — change-to-coin conversion.
	fn verify_g1_pok(new_coin: &[u8; 32], change: &[u8; 32], proof: &[u8], context: &[u8]) -> bool;
	/// Deterministic unspendable pad coin for partial groups.
	fn pad_group(coins: &[[u8; 32]], group_id: u32) -> Vec<[u8; 32]>;
}

/// Trait implemented by the runtime to send an XCM `Transact` to the RWA
/// parachain whenever a `purchase_rwa` is accepted on the ProofHub chain.
///
/// If the HRMP channel is not open the send silently fails (logged only) so
/// `purchase_rwa` itself never errors due to XCM delivery failure.
pub trait RwaPurchaseDispatch {
	fn send(
		rwa_id: [u8; 32],
		nullifier: [u8; 32],
		spend_tag: [u8; 32],
		note_value: u64,
		tx_id: [u8; 16],
		ownership_commitment: [u8; 32],
	);
}

/// No-op implementation used when XCM is not wired (e.g. tests).
pub struct NoopRwaDispatch;
impl RwaPurchaseDispatch for NoopRwaDispatch {
	fn send(_: [u8; 32], _: [u8; 32], _: [u8; 32], _: u64, _: [u8; 16], _: [u8; 32]) {}
}

/// Trait implemented by the runtime to send an XCM `Transact` to the AuthGate
/// parachain whenever a `purchase_access` or `purchase_access_coin` is accepted
/// on the ProofHub chain.
///
/// If the HRMP channel is not open the send silently fails so the purchase
/// extrinsic itself never errors due to XCM delivery failure.
pub trait AccessKeyDispatch {
	fn send(
		app_id: [u8; 32],
		nullifier: [u8; 32],
		tx_id: [u8; 16],
		access_key_commitment: [u8; 32],
	);
}

/// No-op implementation used when XCM is not wired (e.g. tests).
pub struct NoopAccessDispatch;
impl AccessKeyDispatch for NoopAccessDispatch {
	fn send(_: [u8; 32], _: [u8; 32], _: [u8; 16], _: [u8; 32]) {}
}

/// Configuration for a registered Web2 app on ProofHub.
/// Set by sudo via `set_access_config`. The `payment_account` receives the
/// note value when a user successfully purchases an access key.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo, codec::MaxEncodedLen)]
pub struct AppConfig {
	/// Price in planck that the Pedersen / Lelantus note must equal.
	pub price: u64,
	/// AccountId (raw 32 bytes) on ProofHub that receives the payment.
	pub payment_account: [u8; 32],
}

/// Phase 10: public inputs for a v2 one-of-many RWA purchase.
/// SCALE-encoded; BLAKE2-256 of the encoding is the proof context (replay binding).
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct CoinSpendPublic {
	/// Anonymity-set group being spent from.
	pub group_id: u32,
	/// Revealed serial — the nullifier. One spend per serial, ever.
	pub serial: [u8; 32],
	pub rwa_id: [u8; 32],
	pub tx_id: [u8; 16],
	pub ownership_commitment: [u8; 32],
	/// Plain Pedersen change output (v'·G + r'·H), or [0u8;32] when none.
	pub change: [u8; 32],
	/// New coin absorbing the change: new_coin = change + s'·G1.
	/// [0u8;32] when change is [0u8;32].
	pub change_coin: [u8; 32],
}

/// Phase 10: public inputs for a v2 one-of-many withdrawal.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct CoinWithdrawPublic {
	pub group_id: u32,
	pub serial: [u8; 32],
	/// Revealed amount — the proof enforces v == amount exactly (no change).
	pub amount: u64,
	pub destination: [u8; 32],
	pub tx_id: [u8; 16],
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::ConstU32;
	use frame_support::traits::{Currency, ExistenceRequirement};
	use sp_runtime::traits::UniqueSaturatedInto;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type ProofVerifier: super::ProofVerify;
		type Currency: Currency<Self::AccountId>;
		#[pallet::constant]
		type MaxProofSize: Get<u32>;
		#[pallet::constant]
		type MaxRangeProofSize: Get<u32>;
		#[pallet::constant]
		type MaxOutputs: Get<u32>;
		type PoolAccount: Get<<Self as frame_system::Config>::AccountId>;
		/// XCM dispatch: sends a `Transact` to the RWA parachain after a purchase.
		/// Use `NoopRwaDispatch` when XCM is not needed (e.g. tests).
		type RwaDispatch: super::RwaPurchaseDispatch;
		/// XCM dispatch: sends a `Transact` to the AuthGate parachain after a
		/// `purchase_access` or `purchase_access_coin`.
		/// Use `NoopAccessDispatch` when XCM is not needed (e.g. tests).
		type AccessDispatch: super::AccessKeyDispatch;
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
	#[pallet::getter(fn leaves)]
	pub type Leaves<T: Config> =
		StorageValue<_, BoundedVec<[u8; 32], ConstU32<1048576>>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn root_leaf_count)]
	pub type RootLeafCount<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], u32, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn commitment_index)]
	pub type CommitmentIndex<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], u32, OptionQuery>;

	/// RWA price registry: rwa_id → price as u64 planck.
	/// Set by sudo. Zero means the RWA is not available for purchase.
	#[pallet::storage]
	#[pallet::getter(fn rwa_prices)]
	pub type RwaPrices<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], u64, ValueQuery>;

	/// Access-key config: app_id → AppConfig { price, payment_account }.
	/// Set by sudo. Zero price means the app is not available for purchase.
	#[pallet::storage]
	#[pallet::getter(fn access_key_configs)]
	pub type AccessKeyConfigs<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], super::AppConfig, OptionQuery>;

	// --- Phase 10: Lelantus coin groups (anonymity sets) ---

	/// Coins per group, in insertion order. Group size = 1024 (GroupCapacity).
	/// Stored as one blob per group to bound PoV reads at spend time.
	#[pallet::storage]
	pub type CoinGroups<T: Config> =
		StorageMap<_, Blake2_128Concat, u32, BoundedVec<[u8; 32], ConstU32<1024>>, ValueQuery>;

	/// The group currently accepting deposits.
	#[pallet::storage]
	#[pallet::getter(fn current_group)]
	pub type CurrentGroup<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Serial (nullifier) registry — one spend per serial, ever.
	#[pallet::storage]
	pub type SerialUsed<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], bool, ValueQuery>;

	/// Coin → (group, index) registry — duplicate prevention + wallet sync.
	#[pallet::storage]
	pub type CoinLocation<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], (u32, u32), OptionQuery>;

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
		DepositAccepted {
			commitment: [u8; 32],
			new_merkle_root: [u8; 32],
			hints_blob: BoundedVec<u8, ConstU32<4096>>,
		},
		/// A Pedersen note was used to authorise an RWA purchase via XCM.
		RwaPurchaseAuthorized {
			rwa_id: [u8; 32],
			tx_id: [u8; 16],
		},
		/// Sudo set a new price for an RWA.
		RwaPriceSet { rwa_id: [u8; 32], price: u64 },
		/// A Pedersen note was used to authorise an access-key grant via XCM.
		AccessPurchaseAuthorized {
			app_id: [u8; 32],
			tx_id: [u8; 16],
		},
		/// Sudo set or updated an access-key app config.
		AccessConfigSet { app_id: [u8; 32], price: u64 },
		/// A Pedersen note was withdrawn from the pool.
		WithdrawCompleted {
			nullifier: [u8; 32],
			destination: Vec<u8>,
			amount: u64,
		},
		/// Phase 10: a v2 coin entered the current group.
		CoinDeposited {
			coin: [u8; 32],
			group_id: u32,
			index_in_group: u32,
		},
		/// Phase 10: a one-of-many purchase was authorized. The spent coin is
		/// hidden inside group `group_id`; only the serial is revealed.
		CoinPurchaseAuthorized {
			rwa_id: [u8; 32],
			tx_id: [u8; 16],
			group_id: u32,
			/// New coin from change conversion, if any ([0u8;32] = none).
			change_coin: [u8; 32],
		},
		/// Phase 10: a one-of-many withdrawal completed.
		CoinWithdrawCompleted { tx_id: [u8; 16], amount: u64 },
	}

	#[pallet::error]
	pub enum Error<T> {
		ProofVerificationFailed,
		NullifierAlreadyUsed,
		ProofTooLarge,
		RangeProofTooLarge,
		/// The Merkle tree is full (1,048,576 leaves). Cannot accept more deposits.
		TreeFull,
		/// The requested RWA has no price set — not available for purchase.
		RwaPriceNotSet,
		/// The Pedersen commitment does not open to the RWA price.
		NoteValueMismatch,
		/// The commitment opening proof is invalid.
		OpeningProofInvalid,
		/// The input commitment is not in the Merkle tree.
		CommitmentNotFound,
		/// Phase 10: this serial has already been spent.
		SerialAlreadyUsed,
		/// Phase 10: unknown coin group.
		GroupNotFound,
		/// Phase 10: this coin is already registered.
		DuplicateCoin,
		/// Phase 10: the one-of-many proof failed verification.
		OneOfManyInvalid,
		/// Phase 10: change/change_coin fields are inconsistent.
		ChangeMismatch,
		/// The requested app has no config set — not available for purchase.
		AccessAppNotConfigured,
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
								if !seen.insert(*nn) { return InvalidTransaction::BadMandatory.into(); }
							}
						}
						for nullifier in inputs.nullifiers.iter() {
							if NullifierUsed::<T>::get(nullifier) { return InvalidTransaction::Stale.into(); }
						}
						ValidTransaction::with_tag_prefix("ProofSubmission")
							.and_provides(inputs.tx_id)
							.and_provides(inputs.nullifiers.clone())
							.priority(100)
							.longevity(64)
							.propagate(true)
							.build()
					} else { InvalidTransaction::Call.into() }
				}
				Call::purchase_rwa {
					input_commitment,
					opening_proof,
					nullifier,
					rwa_id,
					tx_id,
					change_commitment, ..
				} => {
					if NullifierUsed::<T>::get(*nullifier) {
						return InvalidTransaction::Stale.into();
					}
					if !CommitmentIndex::<T>::contains_key(input_commitment) {
						return InvalidTransaction::BadMandatory.into();
					}
					let price = RwaPrices::<T>::get(*rwa_id);
					if price == 0 {
						return InvalidTransaction::Call.into();
					}
					if opening_proof.len() != 64 {
						return InvalidTransaction::BadProof.into();
					}
					// Binding must match the call: 112 bytes when change present, 80 otherwise.
					let effective = if let Some(cc) = change_commitment {
						match T::ProofVerifier::pedersen_subtract(input_commitment, cc) {
							Some(e) => e,
							None => return InvalidTransaction::BadProof.into(),
						}
					} else {
						*input_commitment
					};
					let binding: alloc::vec::Vec<u8> = if let Some(cc) = change_commitment {
						let mut b = [0u8; 112];
						b[..32].copy_from_slice(nullifier);
						b[32..64].copy_from_slice(rwa_id);
						b[64..80].copy_from_slice(tx_id);
						b[80..112].copy_from_slice(cc);
						b.to_vec()
					} else {
						let mut b = [0u8; 80];
						b[..32].copy_from_slice(nullifier);
						b[32..64].copy_from_slice(rwa_id);
						b[64..80].copy_from_slice(tx_id);
						b.to_vec()
					};
					if !T::ProofVerifier::verify_opening_knowledge(
						price,
						effective,
						opening_proof.as_slice(),
						&binding,
					) {
						return InvalidTransaction::BadProof.into();
					}

					ValidTransaction::with_tag_prefix("ScanRwaPurchase")
						.and_provides(*tx_id)
						.and_provides(*nullifier)
						.and_provides(*input_commitment)
						.priority(100)
						.longevity(64)
						.propagate(true)
						.build()
				}
				Call::withdraw_private {
					commitment,
					nullifier,
					opening_proof,
					value,
					..
				} => {
					if NullifierUsed::<T>::get(*nullifier) {
						return InvalidTransaction::Stale.into();
					}
					if !CommitmentIndex::<T>::contains_key(commitment) {
						return InvalidTransaction::BadMandatory.into();
					}
					if opening_proof.len() != 64 {
						return InvalidTransaction::BadProof.into();
					}
					let mut binding = [0u8; 64];
					binding[..32].copy_from_slice(nullifier);
					binding[32..].copy_from_slice(commitment);
					if !T::ProofVerifier::verify_opening_knowledge(*value, *commitment, opening_proof.as_slice(), &binding) {
						return InvalidTransaction::BadProof.into();
					}
					ValidTransaction::with_tag_prefix("ScanWithdraw")
						.and_provides(*nullifier)
						.priority(100)
						.longevity(u64::MAX)
						.propagate(true)
						.build()
				}
				Call::purchase_coin { public_inputs, .. } => {
					if let Ok(inputs) = CoinSpendPublic::decode(&mut &public_inputs[..]) {
						if SerialUsed::<T>::get(inputs.serial) {
							return InvalidTransaction::Stale.into();
						}
						if !CoinGroups::<T>::contains_key(inputs.group_id) {
							return InvalidTransaction::BadMandatory.into();
						}
						ValidTransaction::with_tag_prefix("ScanCoinPurchase")
							.and_provides(inputs.tx_id)
							.and_provides(inputs.serial)
							.priority(100)
							.longevity(64)
							.propagate(true)
							.build()
					} else { InvalidTransaction::Call.into() }
				}
				Call::withdraw_coin { public_inputs, .. } => {
					if let Ok(inputs) = CoinWithdrawPublic::decode(&mut &public_inputs[..]) {
						if SerialUsed::<T>::get(inputs.serial) {
							return InvalidTransaction::Stale.into();
						}
						if !CoinGroups::<T>::contains_key(inputs.group_id) {
							return InvalidTransaction::BadMandatory.into();
						}
						ValidTransaction::with_tag_prefix("ScanCoinWithdraw")
							.and_provides(inputs.tx_id)
							.and_provides(inputs.serial)
							.priority(100)
							.longevity(64)
							.propagate(true)
							.build()
					} else { InvalidTransaction::Call.into() }
				}
				// ── Access-key lanes ─────────────────────────────────────────────────
				Call::purchase_access {
					input_commitment,
					opening_proof,
					nullifier,
					app_id,
					tx_id,
					change_commitment, ..
				} => {
					if NullifierUsed::<T>::get(*nullifier) {
						return InvalidTransaction::Stale.into();
					}
					if !CommitmentIndex::<T>::contains_key(input_commitment) {
						return InvalidTransaction::BadMandatory.into();
					}
					let cfg = match AccessKeyConfigs::<T>::get(*app_id) {
						Some(c) if c.price > 0 => c,
						_ => return InvalidTransaction::Call.into(),
					};
					if opening_proof.len() != 64 {
						return InvalidTransaction::BadProof.into();
					}
					let effective = if let Some(cc) = change_commitment {
						match T::ProofVerifier::pedersen_subtract(input_commitment, cc) {
							Some(e) => e,
							None => return InvalidTransaction::BadProof.into(),
						}
					} else {
						*input_commitment
					};
					let binding: alloc::vec::Vec<u8> = if let Some(cc) = change_commitment {
						let mut b = [0u8; 112];
						b[..32].copy_from_slice(nullifier);
						b[32..64].copy_from_slice(app_id);
						b[64..80].copy_from_slice(tx_id);
						b[80..112].copy_from_slice(cc);
						b.to_vec()
					} else {
						let mut b = [0u8; 80];
						b[..32].copy_from_slice(nullifier);
						b[32..64].copy_from_slice(app_id);
						b[64..80].copy_from_slice(tx_id);
						b.to_vec()
					};
					if !T::ProofVerifier::verify_opening_knowledge(
						cfg.price,
						effective,
						opening_proof.as_slice(),
						&binding,
					) {
						return InvalidTransaction::BadProof.into();
					}
					ValidTransaction::with_tag_prefix("ScanAccessPurchase")
						.and_provides(*tx_id)
						.and_provides(*nullifier)
						.and_provides(*input_commitment)
						.priority(100)
						.longevity(64)
						.propagate(true)
						.build()
				}
				Call::purchase_access_coin { public_inputs, .. } => {
					if let Ok(inputs) = CoinSpendPublic::decode(&mut &public_inputs[..]) {
						if SerialUsed::<T>::get(inputs.serial) {
							return InvalidTransaction::Stale.into();
						}
						if !CoinGroups::<T>::contains_key(inputs.group_id) {
							return InvalidTransaction::BadMandatory.into();
						}
						ValidTransaction::with_tag_prefix("ScanAccessCoinPurchase")
							.and_provides(inputs.tx_id)
							.and_provides(inputs.serial)
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
			range_proof: BoundedVec<u8, <T as Config>::MaxRangeProofSize>,
			hints_blob: BoundedVec<u8, ConstU32<4096>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(commitment.len() == 32, Error::<T>::ProofVerificationFailed);
			let mut c_arr = [0u8; 32]; c_arr.copy_from_slice(&commitment[..32]);
			// Wire format: [n_proofs:u8=1][proof_len:u32LE][proof_bytes][v:u64LE]
			let rp = range_proof.as_slice();
			ensure!(rp.len() >= 13, Error::<T>::ProofVerificationFailed);
			ensure!(rp[0] == 1, Error::<T>::ProofVerificationFailed);
			let proof_len = u32::from_le_bytes([rp[1], rp[2], rp[3], rp[4]]) as usize;
			ensure!(rp.len() >= 5 + proof_len + 8, Error::<T>::ProofVerificationFailed);
			let bp_bytes = &rp[5..5 + proof_len];
			let amt_u64 = u64::from_le_bytes([
				rp[5+proof_len], rp[5+proof_len+1], rp[5+proof_len+2], rp[5+proof_len+3],
				rp[5+proof_len+4], rp[5+proof_len+5], rp[5+proof_len+6], rp[5+proof_len+7],
			]);
			ensure!(
				T::ProofVerifier::verify_range_proof(bp_bytes, &[c_arr], &[], 64),
				Error::<T>::ProofVerificationFailed
			);
			let pool = T::PoolAccount::get();
			let value: BalanceOf<T> = (amt_u64 as u128).unique_saturated_into();
			T::Currency::transfer(&who, &pool, value, ExistenceRequirement::KeepAlive)?;
			ensure!(!CommitmentIndex::<T>::contains_key(&c_arr), Error::<T>::ProofVerificationFailed);
			let mut leaves = Leaves::<T>::get();
					ensure!(leaves.len() < 1048576, Error::<T>::TreeFull);
					let leaf = Self::leaf_hash(c_arr);
					let idx = leaves.len() as u32;
					leaves.try_push(leaf).map_err(|_| Error::<T>::TreeFull)?;
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
			Self::deposit_event(Event::DepositAccepted { commitment: c_arr, new_merkle_root: computed_root, hints_blob });
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

			let anchor = inputs.merkle_root;
			let current = CurrentRoot::<T>::get();
			if anchor != current {
				let window = RecentRoots::<T>::get();
				ensure!(window.iter().any(|r| *r == anchor), Error::<T>::ProofVerificationFailed);
			}
			{
				let cmts: alloc::vec::Vec<[u8; 32]> = inputs.new_commitments.clone();
				ensure!(cmts.len() as u32 <= T::MaxOutputs::get(), Error::<T>::ProofVerificationFailed);
				let ok = T::ProofVerifier::verify_range_proof(&range_proof, &cmts, &public_inputs, 64);
				ensure!(ok, Error::<T>::ProofVerificationFailed);
			}
			let ok = T::ProofVerifier::verify(&proof, &public_inputs);
			if !ok { Self::deposit_event(Event::ProofRejected); Err(Error::<T>::ProofVerificationFailed)?; }
			let anchor_count = RootLeafCount::<T>::get(anchor);
				for (i, c) in inputs.input_commitments.iter().enumerate() {
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

			{
				let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
				for c in inputs.new_commitments.iter() {
					ensure!(seen.insert(*c), Error::<T>::ProofVerificationFailed);
					ensure!(!CommitmentIndex::<T>::contains_key(c), Error::<T>::ProofVerificationFailed);
				}
			}
				ensure!(inputs.new_commitments.len() as u32 <= T::MaxOutputs::get(), Error::<T>::ProofVerificationFailed);
				let mut leaves = Leaves::<T>::get();
				let space = 1048576usize.saturating_sub(leaves.len());
				ensure!(inputs.new_commitments.len() <= space, Error::<T>::TreeFull);
				for c in inputs.new_commitments.iter() {
					let leaf = Self::leaf_hash(*c);
					let idx = leaves.len() as u32;
					leaves.try_push(leaf).map_err(|_| Error::<T>::TreeFull)?;
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
			Ok(())
		}

		/// Purchase an RWA privately using a Pedersen note.
		///
		/// The caller proves they hold a note (Pedersen commitment) whose value
		/// equals the RWA price via a Schnorr proof of knowledge of the opening
		/// blinding scalar, without revealing it on-chain.
		///
		/// If `change_commitment` is provided, the proof is made against the
		/// homomorphic difference `C_input - C_change`, proving conservation:
		/// `v_input - v_change == price` without revealing either value.
		/// The change note is inserted into the Merkle tree.
		///
		/// On success:
		/// - The nullifier is stored to prevent double-spend.
		/// - An XCM `xcm_record_purchase` is sent to the RWA parachain (para 2001).
		/// - The ownership_commitment (32 bytes) is recorded so the buyer can later
		///   redeem the physical asset on the RWA chain by revealing its blinding.
		///
		/// This is an UNSIGNED extrinsic. The account submitting the transaction is
		/// not part of call origin; privacy is preserved by commitment opening checks
		/// and nullifier anti-replay.
		#[pallet::weight(Weight::zero())]
		pub fn purchase_rwa(
			origin: OriginFor<T>,
			input_commitment: [u8; 32],
			opening_proof: Vec<u8>,
			nullifier: [u8; 32],
			rwa_id: [u8; 32],
			tx_id: [u8; 16],
			ownership_commitment: [u8; 32],
			// Optional change note. If provided, the proof is made against
			// `C_input - C_change` (homomorphic subtraction), proving
			// `v_input - v_change == price` without revealing either value.
			// The change note is inserted into the Merkle tree and remains
			// spendable via its own separately-derived nullifier.
			change_commitment: Option<[u8; 32]>,
		) -> DispatchResult {
			ensure_none(origin)?;

			ensure!(!NullifierUsed::<T>::get(nullifier), Error::<T>::NullifierAlreadyUsed);
			ensure!(CommitmentIndex::<T>::contains_key(&input_commitment), Error::<T>::CommitmentNotFound);

			let price = RwaPrices::<T>::get(rwa_id);
			ensure!(price > 0, Error::<T>::RwaPriceNotSet);

			// Compute effective commitment (homomorphic subtraction if change present)
			let effective = if let Some(cc) = change_commitment {
				ensure!(
					!CommitmentIndex::<T>::contains_key(&cc),
					Error::<T>::ProofVerificationFailed
				);
				T::ProofVerifier::pedersen_subtract(&input_commitment, &cc)
					.ok_or(Error::<T>::ProofVerificationFailed)?
			} else {
				input_commitment
			};

			// Binding: 80 bytes normally, 112 bytes when change is present
			let binding: alloc::vec::Vec<u8> = if let Some(cc) = change_commitment {
				let mut b = [0u8; 112];
				b[..32].copy_from_slice(&nullifier);
				b[32..64].copy_from_slice(&rwa_id);
				b[64..80].copy_from_slice(&tx_id);
				b[80..112].copy_from_slice(&cc);
				b.to_vec()
			} else {
				let mut b = [0u8; 80];
				b[..32].copy_from_slice(&nullifier);
				b[32..64].copy_from_slice(&rwa_id);
				b[64..80].copy_from_slice(&tx_id);
				b.to_vec()
			};

			ensure!(
				opening_proof.len() == 64,
				Error::<T>::OpeningProofInvalid
			);
			ensure!(
				T::ProofVerifier::verify_opening_knowledge(
					price,
					effective,
					opening_proof.as_slice(),
					&binding,
				),
				Error::<T>::OpeningProofInvalid
			);

			NullifierUsed::<T>::insert(nullifier, true);

			// If change is present: insert change note into Merkle tree.
				// The change note remains spendable via its own separately-derived nullifier.
				if let Some(cc) = change_commitment {
					let mut leaves = Leaves::<T>::get();
					ensure!(leaves.len() < 1048576, Error::<T>::TreeFull);
					let leaf = Self::leaf_hash(cc);
					let idx = leaves.len() as u32;
					leaves.try_push(leaf).map_err(|_| Error::<T>::TreeFull)?;
				CommitmentIndex::<T>::insert(&cc, idx);
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
			}

			Self::deposit_event(Event::RwaPurchaseAuthorized { rwa_id, tx_id });

			// Dispatch XCM to RWA chain; failure is swallowed (logged at runtime level).
			// spend_tag is zero — Pedersen scheme does not use ephemeral spend tags.
			T::RwaDispatch::send(rwa_id, nullifier, [0u8; 32], price, tx_id, ownership_commitment);

			Ok(())
		}

		/// Withdraw a Pedersen note from the pool.
		///
		/// The caller proves knowledge of (value, blinding) such that:
		///   commitment = value·G + blinding·H
		/// and provides the nullifier to prevent double-spend.
		/// The commitment must be in the Merkle tree (inserted by deposit_public or
		/// as a change note from purchase_rwa).
		///
		/// Arguments:
		///   commitment  – the 32-byte Pedersen commitment
		///   nullifier   – derive_nullifier(blinding); marks the note as spent
		///   opening_proof – 64-byte Schnorr proof of (value, blinding)
		///   destination – AccountId32 bytes of the recipient
		///   value       – the note value in planck (u64)
		#[pallet::weight(Weight::zero())]
		pub fn withdraw_private(
			origin: OriginFor<T>,
			commitment: [u8; 32],
			nullifier: [u8; 32],
			opening_proof: Vec<u8>,
			destination: Vec<u8>,
			value: u64,
		) -> DispatchResult {
			ensure_none(origin)?;
			ensure!(CommitmentIndex::<T>::contains_key(&commitment), Error::<T>::CommitmentNotFound);
			ensure!(!NullifierUsed::<T>::get(nullifier), Error::<T>::NullifierAlreadyUsed);
			// Binding: nullifier || commitment (replay-protection tied to this specific note)
			let mut binding = [0u8; 64];
			binding[..32].copy_from_slice(&nullifier);
			binding[32..].copy_from_slice(&commitment);
			ensure!(
				T::ProofVerifier::verify_opening_knowledge(value, commitment, &opening_proof, &binding),
				Error::<T>::OpeningProofInvalid
			);
			ensure!(destination.len() == 32, Error::<T>::ProofVerificationFailed);
			let mut dest_bytes = [0u8; 32];
			dest_bytes.copy_from_slice(&destination);
			let dest: T::AccountId = T::AccountId::decode(&mut &dest_bytes[..])
				.map_err(|_| Error::<T>::ProofVerificationFailed)?;
			let pool = T::PoolAccount::get();
			let amount: BalanceOf<T> = (value as u128).unique_saturated_into();
			T::Currency::transfer(&pool, &dest, amount, ExistenceRequirement::AllowDeath)?;
			NullifierUsed::<T>::insert(nullifier, true);
			Self::deposit_event(Event::WithdrawCompleted { nullifier, destination, amount: value });
			Ok(())
		}

		/// Set the price for an RWA (sudo only).
		///
		/// `rwa_id`: first 4 bytes are asset_id as LE u32, remaining bytes are zero.
		/// `price`: value in planck that a Pedersen note must equal to purchase this RWA.
		/// Setting `price` to zero effectively de-lists the RWA.
		#[pallet::weight(Weight::zero())]
		pub fn set_rwa_price(
			origin: OriginFor<T>,
			rwa_id: [u8; 32],
			price: u64,
		) -> DispatchResult {
			ensure_root(origin)?;
			RwaPrices::<T>::insert(rwa_id, price);
			Self::deposit_event(Event::RwaPriceSet { rwa_id, price });
			Ok(())
		}

		/// Set or update the config for a Web2 access-key app (sudo only).
		///
		/// `app_id`: 32-byte identifier matching the one registered on AuthGate.
		/// `price`: value in planck that a note must equal to purchase access.
		///          Setting to zero de-lists the app.
		/// `payment_account`: raw 32-byte AccountId on ProofHub that receives the
		///                     note value when a purchase succeeds.
		#[pallet::weight(Weight::zero())]
		pub fn set_access_config(
			origin: OriginFor<T>,
			app_id: [u8; 32],
			price: u64,
			payment_account: [u8; 32],
		) -> DispatchResult {
			ensure_root(origin)?;
			let cfg = super::AppConfig { price, payment_account };
			AccessKeyConfigs::<T>::insert(app_id, cfg);
			Self::deposit_event(Event::AccessConfigSet { app_id, price });
			Ok(())
		}

		/// Purchase access to a Web2 app privately using a Pedersen note.
		///
		/// Identical to `purchase_rwa` except:
		/// - `app_id` replaces `rwa_id` (identifies the Web2 application)
		/// - `access_key_commitment` replaces `ownership_commitment`
		///   (= BLAKE3("nulla_access_key_v1" || app_id || blinding))
		/// - The note value is transferred to the app's `payment_account` on ProofHub
		/// - XCM is sent to AuthGate (para 2003) instead of the RWA chain
		///
		/// All RWA-related state is completely unchanged.
		///
		/// This is an UNSIGNED extrinsic; privacy is preserved via commitment
		/// opening checks and nullifier anti-replay.
		#[pallet::weight(Weight::zero())]
		pub fn purchase_access(
			origin: OriginFor<T>,
			input_commitment: [u8; 32],
			opening_proof: Vec<u8>,
			nullifier: [u8; 32],
			app_id: [u8; 32],
			tx_id: [u8; 16],
			access_key_commitment: [u8; 32],
			change_commitment: Option<[u8; 32]>,
		) -> DispatchResult {
			ensure_none(origin)?;

			ensure!(!NullifierUsed::<T>::get(nullifier), Error::<T>::NullifierAlreadyUsed);
			ensure!(CommitmentIndex::<T>::contains_key(&input_commitment), Error::<T>::CommitmentNotFound);

			let cfg = AccessKeyConfigs::<T>::get(app_id)
				.ok_or(Error::<T>::AccessAppNotConfigured)?;
			ensure!(cfg.price > 0, Error::<T>::AccessAppNotConfigured);

			// Homomorphic subtraction when change note is present.
			let effective = if let Some(cc) = change_commitment {
				ensure!(
					!CommitmentIndex::<T>::contains_key(&cc),
					Error::<T>::ProofVerificationFailed
				);
				T::ProofVerifier::pedersen_subtract(&input_commitment, &cc)
					.ok_or(Error::<T>::ProofVerificationFailed)?
			} else {
				input_commitment
			};

			// Binding: nullifier || app_id || tx_id [|| change_commitment]
			let binding: alloc::vec::Vec<u8> = if let Some(cc) = change_commitment {
				let mut b = [0u8; 112];
				b[..32].copy_from_slice(&nullifier);
				b[32..64].copy_from_slice(&app_id);
				b[64..80].copy_from_slice(&tx_id);
				b[80..112].copy_from_slice(&cc);
				b.to_vec()
			} else {
				let mut b = [0u8; 80];
				b[..32].copy_from_slice(&nullifier);
				b[32..64].copy_from_slice(&app_id);
				b[64..80].copy_from_slice(&tx_id);
				b.to_vec()
			};

			ensure!(opening_proof.len() == 64, Error::<T>::OpeningProofInvalid);
			ensure!(
				T::ProofVerifier::verify_opening_knowledge(
					cfg.price,
					effective,
					opening_proof.as_slice(),
					&binding,
				),
				Error::<T>::OpeningProofInvalid
			);

			NullifierUsed::<T>::insert(nullifier, true);

			// Transfer note value from pool to the app's payment account on ProofHub.
			let payment_dest: T::AccountId =
				T::AccountId::decode(&mut &cfg.payment_account[..])
					.map_err(|_| Error::<T>::ProofVerificationFailed)?;
			let pool = T::PoolAccount::get();
			let amount: BalanceOf<T> = (cfg.price as u128).unique_saturated_into();
			T::Currency::transfer(&pool, &payment_dest, amount, ExistenceRequirement::AllowDeath)?;

			// Insert change note into Merkle tree if present.
			if let Some(cc) = change_commitment {
				let mut leaves = Leaves::<T>::get();
				ensure!(leaves.len() < 1048576, Error::<T>::TreeFull);
				let leaf = Self::leaf_hash(cc);
				let idx = leaves.len() as u32;
				leaves.try_push(leaf).map_err(|_| Error::<T>::TreeFull)?;
				CommitmentIndex::<T>::insert(&cc, idx);
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
			}

			Self::deposit_event(Event::AccessPurchaseAuthorized { app_id, tx_id });

			// XCM to AuthGate (para 2003): nullifier, tx_id, access_key_commitment.
			T::AccessDispatch::send(app_id, nullifier, tx_id, access_key_commitment);

			Ok(())
		}

		/// Phase 10: deposit a v2 Lelantus coin into the current group.
		///
		/// SIGNED — the depositor pays `amount` into the pool (cash-in boundary,
		/// inherently public). The coin C = s·G1 + v·G + r·H reveals nothing about
		/// (s, r); `open_proof` (96 B) proves C − amount·G = s·G1 + r·H, so the
		/// hidden value always equals the paid amount.
		///
		/// Unlike v1, the coin is never named again: spends prove one-of-many
		/// membership over the whole group without revealing which coin.
		#[pallet::weight((Weight::zero(), Pays::No))]
		pub fn deposit_coin(
			origin: OriginFor<T>,
			coin: [u8; 32],
			amount: u64,
			open_proof: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!CoinLocation::<T>::contains_key(&coin), Error::<T>::DuplicateCoin);
			let ctx = who.encode();
			ensure!(
				T::ProofVerifier::verify_deposit_open(&coin, amount, &open_proof, &ctx),
				Error::<T>::OpeningProofInvalid
			);
			let pool = T::PoolAccount::get();
			let value: BalanceOf<T> = (amount as u128).unique_saturated_into();
			T::Currency::transfer(&who, &pool, value, ExistenceRequirement::KeepAlive)?;

			let mut gid = CurrentGroup::<T>::get();
			let mut group = CoinGroups::<T>::get(gid);
			if group.len() >= 1024 {
				gid += 1;
				CurrentGroup::<T>::put(gid);
				group = CoinGroups::<T>::get(gid);
			}
			let idx = group.len() as u32;
			group.try_push(coin).map_err(|_| Error::<T>::TreeFull)?;
			CoinGroups::<T>::insert(gid, &group);
			CoinLocation::<T>::insert(&coin, (gid, idx));
			Self::deposit_event(Event::CoinDeposited { coin, group_id: gid, index_in_group: idx });
			Ok(())
		}

		/// Phase 10: purchase an RWA via one-of-many proof — TRUE unlinkability.
		///
		/// UNSIGNED. Reveals only: group_id, serial, action fields, and the
		/// change output. The spent coin remains hidden in a 1024-coin
		/// anonymity set (the proof shows "one of these coins, minus the
		/// serial and price (and change), opens to a blinding I know").
		///
		/// When `change != [0;32]`, `change_coin = change + s'·G1` is
		/// registered as a new spendable coin; `g1_pok` (64 B) proves the
		/// conversion adds only a serial term (value is conserved).
		#[pallet::weight(Weight::zero())]
		pub fn purchase_coin(
			origin: OriginFor<T>,
			public_inputs: Vec<u8>,
			one_of_many_proof: Vec<u8>,
			g1_pok: Vec<u8>,
		) -> DispatchResult {
			ensure_none(origin)?;

			let inputs = CoinSpendPublic::decode(&mut &public_inputs[..])
				.map_err(|_| Error::<T>::ProofVerificationFailed)?;

			ensure!(!SerialUsed::<T>::get(inputs.serial), Error::<T>::SerialAlreadyUsed);
			ensure!(CoinGroups::<T>::contains_key(inputs.group_id), Error::<T>::GroupNotFound);

			let price = RwaPrices::<T>::get(inputs.rwa_id);
			ensure!(price > 0, Error::<T>::RwaPriceNotSet);

			// Change consistency: both present or both absent.
			let has_change = inputs.change != [0u8; 32];
			ensure!(has_change == (inputs.change_coin != [0u8; 32]), Error::<T>::ChangeMismatch);

			// Pad partial groups deterministically (pad coins are unspendable).
			let group = CoinGroups::<T>::get(inputs.group_id);
			let coins = T::ProofVerifier::pad_group(&group, inputs.group_id);

			// Context binds the proof to this exact transaction.
			let ctx = blake2_256(&public_inputs);
			ensure!(
				T::ProofVerifier::verify_one_of_many(
					&one_of_many_proof, &coins, &inputs.serial, price, &inputs.change, &ctx,
				),
				Error::<T>::OneOfManyInvalid
			);

			// Register the change coin (value-conserving conversion).
			if has_change {
				ensure!(!CoinLocation::<T>::contains_key(&inputs.change_coin), Error::<T>::DuplicateCoin);
				ensure!(
					T::ProofVerifier::verify_g1_pok(&inputs.change_coin, &inputs.change, &g1_pok, &ctx),
					Error::<T>::OpeningProofInvalid
				);
				let mut gid = CurrentGroup::<T>::get();
				let mut grp = CoinGroups::<T>::get(gid);
				if grp.len() >= 1024 {
					gid += 1;
					CurrentGroup::<T>::put(gid);
					grp = CoinGroups::<T>::get(gid);
				}
				let idx = grp.len() as u32;
				grp.try_push(inputs.change_coin).map_err(|_| Error::<T>::TreeFull)?;
				CoinGroups::<T>::insert(gid, &grp);
				CoinLocation::<T>::insert(&inputs.change_coin, (gid, idx));
				Self::deposit_event(Event::CoinDeposited {
					coin: inputs.change_coin, group_id: gid, index_in_group: idx,
				});
			}

			SerialUsed::<T>::insert(inputs.serial, true);

			Self::deposit_event(Event::CoinPurchaseAuthorized {
				rwa_id: inputs.rwa_id,
				tx_id: inputs.tx_id,
				group_id: inputs.group_id,
				change_coin: inputs.change_coin,
			});

			// XCM to the RWA chain: nullifier/spend_tag slots carry the serial
			// (already public).
			T::RwaDispatch::send(
				inputs.rwa_id,
				inputs.serial,
				inputs.serial,
				price,
				inputs.tx_id,
				inputs.ownership_commitment,
			);

			Ok(())
		}

		/// Phase 10: withdraw a v2 coin back to public balance via one-of-many proof.
		///
		/// UNSIGNED. The proof enforces v == amount exactly (no change term).
		#[pallet::weight(Weight::zero())]
		pub fn withdraw_coin(
			origin: OriginFor<T>,
			public_inputs: Vec<u8>,
			one_of_many_proof: Vec<u8>,
		) -> DispatchResult {
			ensure_none(origin)?;

			let inputs = CoinWithdrawPublic::decode(&mut &public_inputs[..])
				.map_err(|_| Error::<T>::ProofVerificationFailed)?;

			ensure!(!SerialUsed::<T>::get(inputs.serial), Error::<T>::SerialAlreadyUsed);
			ensure!(CoinGroups::<T>::contains_key(inputs.group_id), Error::<T>::GroupNotFound);

			let group = CoinGroups::<T>::get(inputs.group_id);
			let coins = T::ProofVerifier::pad_group(&group, inputs.group_id);

			let ctx = blake2_256(&public_inputs);
			ensure!(
				T::ProofVerifier::verify_one_of_many(
					&one_of_many_proof, &coins, &inputs.serial, inputs.amount, &[0u8; 32], &ctx,
				),
				Error::<T>::OneOfManyInvalid
			);

			SerialUsed::<T>::insert(inputs.serial, true);

			let dest: T::AccountId = T::AccountId::decode(&mut &inputs.destination[..])
				.map_err(|_| Error::<T>::ProofVerificationFailed)?;
			let pool = T::PoolAccount::get();
			let value: BalanceOf<T> = (inputs.amount as u128).unique_saturated_into();
			T::Currency::transfer(&pool, &dest, value, ExistenceRequirement::AllowDeath)?;

			Self::deposit_event(Event::CoinWithdrawCompleted {
				tx_id: inputs.tx_id,
				amount: inputs.amount,
			});
			Ok(())
		}

		/// Phase 10 (Lelantus): purchase access to a Web2 app via one-of-many proof.
		///
		/// Identical to `purchase_coin` except:
		/// - Uses `AccessKeyConfigs` (app_id → price) instead of `RwaPrices`
		/// - Transfers price from pool to the app's `payment_account` on ProofHub
		/// - Sends XCM to AuthGate (para 2003) via `T::AccessDispatch`
		///
		/// The `public_inputs` is a SCALE-encoded `CoinSpendPublic` where:
		/// - `rwa_id` carries the `app_id`
		/// - `ownership_commitment` carries the `access_key_commitment`
		///
		/// UNSIGNED. All RWA state (`purchase_coin`) is completely unchanged.
		#[pallet::weight(Weight::zero())]
		pub fn purchase_access_coin(
			origin: OriginFor<T>,
			public_inputs: Vec<u8>,
			one_of_many_proof: Vec<u8>,
			g1_pok: Vec<u8>,
		) -> DispatchResult {
			ensure_none(origin)?;

			let inputs = CoinSpendPublic::decode(&mut &public_inputs[..])
				.map_err(|_| Error::<T>::ProofVerificationFailed)?;

			ensure!(!SerialUsed::<T>::get(inputs.serial), Error::<T>::SerialAlreadyUsed);
			ensure!(CoinGroups::<T>::contains_key(inputs.group_id), Error::<T>::GroupNotFound);

			// rwa_id field carries app_id in this lane
			let app_id = inputs.rwa_id;
			let cfg = AccessKeyConfigs::<T>::get(app_id)
				.ok_or(Error::<T>::AccessAppNotConfigured)?;
			ensure!(cfg.price > 0, Error::<T>::AccessAppNotConfigured);

			let has_change = inputs.change != [0u8; 32];
			ensure!(has_change == (inputs.change_coin != [0u8; 32]), Error::<T>::ChangeMismatch);

			let group = CoinGroups::<T>::get(inputs.group_id);
			let coins = T::ProofVerifier::pad_group(&group, inputs.group_id);

			let ctx = blake2_256(&public_inputs);
			ensure!(
				T::ProofVerifier::verify_one_of_many(
					&one_of_many_proof, &coins, &inputs.serial, cfg.price, &inputs.change, &ctx,
				),
				Error::<T>::OneOfManyInvalid
			);

			// Register change coin if present.
			if has_change {
				ensure!(!CoinLocation::<T>::contains_key(&inputs.change_coin), Error::<T>::DuplicateCoin);
				ensure!(
					T::ProofVerifier::verify_g1_pok(&inputs.change_coin, &inputs.change, &g1_pok, &ctx),
					Error::<T>::OpeningProofInvalid
				);
				let mut gid = CurrentGroup::<T>::get();
				let mut grp = CoinGroups::<T>::get(gid);
				if grp.len() >= 1024 {
					gid += 1;
					CurrentGroup::<T>::put(gid);
					grp = CoinGroups::<T>::get(gid);
				}
				let idx = grp.len() as u32;
				grp.try_push(inputs.change_coin).map_err(|_| Error::<T>::TreeFull)?;
				CoinGroups::<T>::insert(gid, &grp);
				CoinLocation::<T>::insert(&inputs.change_coin, (gid, idx));
				Self::deposit_event(Event::CoinDeposited {
					coin: inputs.change_coin, group_id: gid, index_in_group: idx,
				});
			}

			SerialUsed::<T>::insert(inputs.serial, true);

			// Transfer price from pool to app payment account on ProofHub.
			let payment_dest: T::AccountId =
				T::AccountId::decode(&mut &cfg.payment_account[..])
					.map_err(|_| Error::<T>::ProofVerificationFailed)?;
			let pool = T::PoolAccount::get();
			let amount: BalanceOf<T> = (cfg.price as u128).unique_saturated_into();
			T::Currency::transfer(&pool, &payment_dest, amount, ExistenceRequirement::AllowDeath)?;

			// ownership_commitment field carries access_key_commitment in this lane
			let access_key_commitment = inputs.ownership_commitment;
			let tx_id = inputs.tx_id;

			Self::deposit_event(Event::AccessPurchaseAuthorized { app_id, tx_id });

			// XCM to AuthGate (para 2003).
			T::AccessDispatch::send(app_id, inputs.serial, tx_id, access_key_commitment);

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
