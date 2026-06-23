// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org>

mod xcm_config;

use polkadot_sdk::{staging_parachain_info as parachain_info, staging_xcm as xcm, *};
#[cfg(not(feature = "runtime-benchmarks"))]
use polkadot_sdk::{staging_xcm_builder as xcm_builder, staging_xcm_executor as xcm_executor};

// Substrate and Polkadot dependencies
use cumulus_pallet_parachain_system::RelayNumberMonotonicallyIncreases;
use cumulus_primitives_core::{AggregateMessageOrigin, ParaId};
use frame_support::{
	derive_impl,
	dispatch::DispatchClass,
	parameter_types,
	traits::{
		ConstBool, ConstU32, ConstU64, ConstU8, EitherOfDiverse, TransformOrigin, VariantCountOf,
	},
	weights::{ConstantMultiplier, Weight},
	PalletId,
};
use frame_system::{
	limits::{BlockLength, BlockWeights},
	EnsureRoot,
};
use pallet_xcm::{EnsureXcm, IsVoiceOfBody};
use parachains_common::message_queue::{NarrowOriginToSibling, ParaIdToSibling};
use polkadot_runtime_common::{
	xcm_sender::ExponentialPrice, BlockHashCount, SlowAdjustingFeeUpdate,
};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_runtime::Perbill;
use sp_runtime::traits::AccountIdConversion;
use sp_version::RuntimeVersion;
use xcm::latest::prelude::{AssetId, BodyId};

// Local module imports
use super::{
	weights::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight},
	AccountId, Aura, Balance, Balances, Block, BlockNumber, CollatorSelection, ConsensusHook, Hash,
	MessageQueue, Nonce, PalletInfo, ParachainSystem, Runtime, RuntimeCall, RuntimeEvent,
	RuntimeFreezeReason, RuntimeHoldReason, RuntimeOrigin, RuntimeTask, Session, SessionKeys,
	System, WeightToFee, XcmpQueue, AVERAGE_ON_INITIALIZE_RATIO, CENTS, EXISTENTIAL_DEPOSIT, HOURS,
	MAXIMUM_BLOCK_WEIGHT, MICRO_UNIT, NORMAL_DISPATCH_RATIO, SLOT_DURATION, VERSION,
};
use xcm_config::{RelayLocation, XcmOriginToTransactDispatchOrigin};

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;

	// This part is copied from Substrate's `bin/node/runtime/src/lib.rs`.
	//  The `RuntimeBlockLength` and `RuntimeBlockWeights` exist here because the
	// `DeletionWeightLimit` and `DeletionQueueDepth` depend on those to parameterize
	// the lazy contract deletion.
	pub RuntimeBlockLength: BlockLength =
		BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
		.base_block(BlockExecutionWeight::get())
		.for_class(DispatchClass::all(), |weights| {
			weights.base_extrinsic = ExtrinsicBaseWeight::get();
		})
		.for_class(DispatchClass::Normal, |weights| {
			weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
		})
		.for_class(DispatchClass::Operational, |weights| {
			weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
			// Operational transactions have some extra reserved space, so that they
			// are included even if block reached `MAXIMUM_BLOCK_WEIGHT`.
			weights.reserved = Some(
				MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT
			);
		})
		.avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
		.build_or_panic();
	pub const SS58Prefix: u16 = 42;
}

/// All migrations of the runtime, aside from the ones declared in the pallets.
///
/// This can be a tuple of types, each implementing `OnRuntimeUpgrade`.
#[allow(unused_parens)]
type SingleBlockMigrations = ();

/// The default types are being injected by [`derive_impl`](`frame_support::derive_impl`) from
/// [`ParaChainDefaultConfig`](`struct@frame_system::config_preludes::ParaChainDefaultConfig`),
/// but overridden as needed.
#[derive_impl(frame_system::config_preludes::ParaChainDefaultConfig)]
impl frame_system::Config for Runtime {
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The index type for storing how many extrinsics an account has signed.
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The block type.
	type Block = Block;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// Runtime version.
	type Version = Version;
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = RuntimeBlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = RuntimeBlockLength;
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	/// The action to take on a Runtime Upgrade
	type OnSetCode = cumulus_pallet_parachain_system::ParachainSetCode<Self>;
	type MaxConsumers = frame_support::traits::ConstU32<16>;
	type SingleBlockMigrations = SingleBlockMigrations;
}

/// Configure the palelt weight reclaim tx.
impl cumulus_pallet_weight_reclaim::Config for Runtime {
	type WeightInfo = ();
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = Aura;
	type MinimumPeriod = ConstU64<0>;
	type WeightInfo = ();
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Aura>;
	type EventHandler = (CollatorSelection,);
}

parameter_types! {
	pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
}

impl pallet_balances::Config for Runtime {
	type MaxLocks = ConstU32<50>;
	/// The type for recording an account's balance.
	type Balance = Balance;
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
	type MaxReserves = ConstU32<50>;
	type ReserveIdentifier = [u8; 8];
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
	type DoneSlashHandler = ();
}

parameter_types! {
	/// Relay Chain `TransactionByteFee` / 10
	pub const TransactionByteFee: Balance = 10 * MICRO_UNIT;
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
	type WeightToFee = WeightToFee;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Self>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightInfo = ();
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = ();
}

parameter_types! {
	pub const ReservedXcmpWeight: Weight = MAXIMUM_BLOCK_WEIGHT.saturating_div(4);
	pub const ReservedDmpWeight: Weight = MAXIMUM_BLOCK_WEIGHT.saturating_div(4);
	pub const RelayOrigin: AggregateMessageOrigin = AggregateMessageOrigin::Parent;
}

impl cumulus_pallet_parachain_system::Config for Runtime {
	type WeightInfo = ();
	type RuntimeEvent = RuntimeEvent;
	type OnSystemEvent = ();
	type SelfParaId = parachain_info::Pallet<Runtime>;
	type OutboundXcmpMessageSource = XcmpQueue;
	type DmpQueue = frame_support::traits::EnqueueWithOrigin<MessageQueue, RelayOrigin>;
	type ReservedDmpWeight = ReservedDmpWeight;
	type XcmpMessageHandler = XcmpQueue;
	type ReservedXcmpWeight = ReservedXcmpWeight;
	type CheckAssociatedRelayNumber = RelayNumberMonotonicallyIncreases;
	type ConsensusHook = ConsensusHook;
	type RelayParentOffset = ConstU32<0>;
}

impl parachain_info::Config for Runtime {}

parameter_types! {
	pub MessageQueueServiceWeight: Weight = Perbill::from_percent(35) * RuntimeBlockWeights::get().max_block;
}

impl pallet_message_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	#[cfg(feature = "runtime-benchmarks")]
	type MessageProcessor = pallet_message_queue::mock_helpers::NoopMessageProcessor<
		cumulus_primitives_core::AggregateMessageOrigin,
	>;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type MessageProcessor = xcm_builder::ProcessXcmMessage<
		AggregateMessageOrigin,
		xcm_executor::XcmExecutor<xcm_config::XcmConfig>,
		RuntimeCall,
	>;
	type Size = u32;
	// The XCMP queue pallet is only ever able to handle the `Sibling(ParaId)` origin:
	type QueueChangeHandler = NarrowOriginToSibling<XcmpQueue>;
	type QueuePausedQuery = NarrowOriginToSibling<XcmpQueue>;
	type HeapSize = sp_core::ConstU32<{ 103 * 1024 }>;
	type MaxStale = sp_core::ConstU32<8>;
	type ServiceWeight = MessageQueueServiceWeight;
	type IdleMaxServiceWeight = ();
}

impl cumulus_pallet_aura_ext::Config for Runtime {}

parameter_types! {
	/// The asset ID for the asset that we use to pay for message delivery fees.
	pub FeeAssetId: AssetId = AssetId(xcm_config::RelayLocation::get());
	/// The base fee for the message delivery fees.
	pub const ToSiblingBaseDeliveryFee: u128 = CENTS.saturating_mul(3);
	pub const ToParentBaseDeliveryFee: u128 = CENTS.saturating_mul(3);
}

/// The price for delivering XCM messages to sibling parachains.
pub type PriceForSiblingParachainDelivery =
	ExponentialPrice<FeeAssetId, ToSiblingBaseDeliveryFee, TransactionByteFee, XcmpQueue>;

/// The price for delivering XCM messages to relay chain.
pub type PriceForParentDelivery =
	ExponentialPrice<FeeAssetId, ToParentBaseDeliveryFee, TransactionByteFee, ParachainSystem>;

impl cumulus_pallet_xcmp_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ChannelInfo = ParachainSystem;
	type VersionWrapper = ();
	// Enqueue XCMP messages from siblings for later processing.
	type XcmpQueue = TransformOrigin<MessageQueue, AggregateMessageOrigin, ParaId, ParaIdToSibling>;
	type MaxInboundSuspended = sp_core::ConstU32<1_000>;
	type MaxActiveOutboundChannels = ConstU32<128>;
	type MaxPageSize = ConstU32<{ 1 << 16 }>;
	type ControllerOrigin = EnsureRoot<AccountId>;
	type ControllerOriginConverter = XcmOriginToTransactDispatchOrigin;
	type WeightInfo = ();
	type PriceForSiblingDelivery = PriceForSiblingParachainDelivery;
}

parameter_types! {
	pub const Period: u32 = 6 * HOURS;
	pub const Offset: u32 = 0;
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	// we don't have stash and controller, thus we don't need the convert as well.
	type ValidatorIdOf = pallet_collator_selection::IdentityCollator;
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	type SessionManager = CollatorSelection;
	// Essentially just Aura, but let's be pedantic.
	type SessionHandler = <SessionKeys as sp_runtime::traits::OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type DisablingStrategy = ();
	type WeightInfo = ();
	type Currency = Balances;
	type KeyDeposit = ();
}

#[docify::export(aura_config)]
impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type MaxAuthorities = ConstU32<100_000>;
	type AllowMultipleBlocksPerSlot = ConstBool<true>;
	type SlotDuration = ConstU64<SLOT_DURATION>;
}

parameter_types! {
	pub const PotId: PalletId = PalletId(*b"PotStake");
	pub const SessionLength: BlockNumber = 6 * HOURS;
	// StakingAdmin pluralistic body.
	pub const StakingAdminBodyId: BodyId = BodyId::Defense;
}

/// We allow root and the StakingAdmin to execute privileged collator selection operations.
pub type CollatorSelectionUpdateOrigin = EitherOfDiverse<
	EnsureRoot<AccountId>,
	EnsureXcm<IsVoiceOfBody<RelayLocation, StakingAdminBodyId>>,
>;

impl pallet_collator_selection::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type UpdateOrigin = CollatorSelectionUpdateOrigin;
	type PotId = PotId;
	type MaxCandidates = ConstU32<100>;
	type MinEligibleCollators = ConstU32<4>;
	type MaxInvulnerables = ConstU32<20>;
	// should be a multiple of session or things will get inconsistent
	type KickThreshold = Period;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type ValidatorIdOf = pallet_collator_selection::IdentityCollator;
	type ValidatorRegistration = Session;
	type WeightInfo = ();
}

/// Configure the ProofHub template pallet.
impl pallet_parachain_template::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_parachain_template::weights::SubstrateWeight<Runtime>;
}

/// Configure the proofs pallet.
impl pallet_proofs::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ProofVerifier = RuntimeProofVerifier;
	type Currency = Balances;
	type MaxProofSize = sp_core::ConstU32<{ 64 * 1024 }>;
	type MaxRangeProofSize = sp_core::ConstU32<{ 16 * 1024 }>;
	type MaxOutputs = sp_core::ConstU32<2>;
	type PoolAccount = PrivacyPoolAccount;
	type RwaDispatch = RwaXcmDispatch;
	type AccessDispatch = AccessGateXcmDispatch;
}

// Runtime proof verifier wired to the local `verifier` crate.
pub struct RuntimeProofVerifier;
impl pallet_proofs::ProofVerify for RuntimeProofVerifier {
	fn verify(proof: &[u8], public_inputs: &[u8]) -> bool {
		verifier::verify_bytes(proof, public_inputs)
	}
	fn verify_commitment(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool {
		verifier::verify_commitment(value, blinding, commitment)
	}
	fn verify_opening_knowledge(
		value: u64,
		commitment: [u8; 32],
		proof: &[u8],
		binding: &[u8],
	) -> bool {
		verifier::verify_opening_knowledge(value, commitment, proof, binding)
	}
	fn verify_range_proof(
		range_proof: &[u8],
		commitments: &[[u8; 32]],
		public_inputs: &[u8],
		nbits: u32,
	) -> bool {
		verifier::verify_range_proof(range_proof, commitments, public_inputs, nbits)
	}
	fn pedersen_subtract(c_a: &[u8; 32], c_b: &[u8; 32]) -> Option<[u8; 32]> {
		verifier::pedersen_subtract(c_a, c_b)
	}

	// --- Phase 10 (Lelantus one-of-many) ---

	fn verify_one_of_many(
		proof: &[u8],
		coins: &[[u8; 32]],
		serial: &[u8; 32],
		price: u64,
		change: &[u8; 32],
		context: &[u8],
	) -> bool {
		verifier::one_of_many::verify(proof, coins, serial, price, change, context)
	}
	fn verify_deposit_open(coin: &[u8; 32], amount: u64, proof: &[u8], context: &[u8]) -> bool {
		verifier::one_of_many::verify_deposit_open(coin, amount, proof, context)
	}
	fn verify_g1_pok(new_coin: &[u8; 32], change: &[u8; 32], proof: &[u8], context: &[u8]) -> bool {
		verifier::one_of_many::verify_g1_pok(new_coin, change, proof, context)
	}
	fn pad_group(coins: &[[u8; 32]], group_id: u32) -> alloc::vec::Vec<[u8; 32]> {
		verifier::one_of_many::pad_group(coins, group_id)
	}
}

parameter_types! {
	pub const PoolPalletId: PalletId = PalletId(*b"nll/pool");
}

pub struct PrivacyPoolAccount;
impl frame_support::traits::Get<AccountId> for PrivacyPoolAccount {
	fn get() -> AccountId { PoolPalletId::get().into_account_truncating() }
}

/// XCM dispatcher: sends a `Transact` to the RWA parachain (para 2001) so that
/// `pallet_rwa_marketplace::xcm_record_purchase` is executed there.
///
/// The origin arriving at the RWA chain is the Pedersen ProofHub sovereign account
/// (para 2002), accepted by the RWA chain alongside the quantum ProofHub sovereign (para 2000).
///
/// If the HRMP channel is not open, `XcmRouter::deliver` returns an error which
/// is swallowed — `purchase_rwa` itself must not fail due to XCM delivery issues.
pub struct RwaXcmDispatch;
impl pallet_proofs::RwaPurchaseDispatch for RwaXcmDispatch {
	fn send(
		rwa_id: [u8; 32],
		nullifier: [u8; 32],
		spend_tag: [u8; 32],
		_note_value: u64,
		tx_id: [u8; 16],
		ownership_commitment: [u8; 32],
	) {
		use codec::Encode;
		use xcm::latest::prelude::*;

		// asset_id: first 4 bytes of rwa_id (LE u32).
		let asset_id = u32::from_le_bytes([rwa_id[0], rwa_id[1], rwa_id[2], rwa_id[3]]);

		// Encode call: [pallet_index=51][call_index=4][args SCALE]
		// Matches RWA runtime: pallet_index(51) = RwaMarketplace, call_index(4) = xcm_record_purchase
		let mut call_data = alloc::vec::Vec::new();
		call_data.push(51u8); // RwaMarketplace pallet index
		call_data.push(4u8);  // xcm_record_purchase call index
		asset_id.encode_to(&mut call_data);
		spend_tag.encode_to(&mut call_data);
		nullifier.encode_to(&mut call_data);
		tx_id.encode_to(&mut call_data);
		ownership_commitment.encode_to(&mut call_data);

		let dest: Location = Location::new(1, Junctions::from([Junction::Parachain(2001)]));
		let xcm_msg: xcm::latest::Xcm<()> = Xcm::<()>(alloc::vec![
			Instruction::<()>::UnpaidExecution {
				weight_limit: WeightLimit::Unlimited,
				check_origin: None,
			},
			Instruction::<()>::Transact {
				origin_kind: OriginKind::SovereignAccount,
				fallback_max_weight: Some(Weight::from_parts(500_000_000, 64 * 1024)),
				call: call_data.into(),
			},
		]);

		let mut dest_opt = Some(dest);
		let mut msg_opt = Some(xcm_msg);
		match xcm_config::XcmRouter::validate(&mut dest_opt, &mut msg_opt) {
			Ok((ticket, _)) => {
				if let Err(e) = xcm_config::XcmRouter::deliver(ticket) {
					log::debug!(target: "proofhub_pedersen::xcm", "RWA purchase XCM deliver failed: {:?}", e);
				}
			}
			Err(e) => {
				log::debug!(target: "proofhub_pedersen::xcm", "RWA purchase XCM validate failed: {:?}", e);
			}
		}
	}
}

/// XCM dispatcher: sends a `Transact` to the AuthGate parachain (para 2003) so that
/// `pallet_access_keys::xcm_record_access_grant` is executed there.
///
/// The origin arriving at AuthGate is the ScanProofHub sovereign account (Sibling(2002)),
/// which is in the AuthGate allowed-sovereign list.
///
/// Silently swallows XCM delivery errors — `purchase_access` must not fail due to XCM issues.
pub struct AccessGateXcmDispatch;
impl pallet_proofs::AccessKeyDispatch for AccessGateXcmDispatch {
	fn send(
		app_id: [u8; 32],
		nullifier: [u8; 32],
		tx_id: [u8; 16],
		access_key_commitment: [u8; 32],
	) {
		use codec::Encode;
		use xcm::latest::prelude::*;

		// Encode call: [pallet_index=50][call_index=2][args SCALE]
		// Matches AuthGate runtime: pallet_index(50) = AccessKeys, call_index(2) = xcm_record_access_grant
		let mut call_data = alloc::vec::Vec::new();
		call_data.push(50u8); // AccessKeys pallet index
		call_data.push(2u8);  // xcm_record_access_grant call index
		app_id.encode_to(&mut call_data);
		nullifier.encode_to(&mut call_data);
		tx_id.encode_to(&mut call_data);
		access_key_commitment.encode_to(&mut call_data);

		let dest: Location = Location::new(1, Junctions::from([Junction::Parachain(2003)]));
		let xcm_msg: xcm::latest::Xcm<()> = Xcm::<()>(alloc::vec![
			Instruction::<()>::UnpaidExecution {
				weight_limit: WeightLimit::Unlimited,
				check_origin: None,
			},
			Instruction::<()>::Transact {
				origin_kind: OriginKind::SovereignAccount,
				fallback_max_weight: Some(Weight::from_parts(500_000_000, 64 * 1024)),
				call: call_data.into(),
			},
		]);

		let mut dest_opt = Some(dest);
		let mut msg_opt = Some(xcm_msg);
		match xcm_config::XcmRouter::validate(&mut dest_opt, &mut msg_opt) {
			Ok((ticket, _)) => {
				if let Err(e) = xcm_config::XcmRouter::deliver(ticket) {
					log::debug!(target: "proofhub_pedersen::xcm", "AccessGate XCM deliver failed: {:?}", e);
				}
			}
			Err(e) => {
				log::debug!(target: "proofhub_pedersen::xcm", "AccessGate XCM validate failed: {:?}", e);
			}
		}
	}
}
