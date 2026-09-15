use super::PriceForParentDelivery;
use crate::{
    AccountId, AllPalletsWithSystem, Balances, ParachainInfo, ParachainSystem, PolkadotXcm,
    Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin, WeightToFee, XcmpQueue,
};

use polkadot_sdk::{
    staging_xcm as xcm, staging_xcm_builder as xcm_builder,
    staging_xcm_executor as xcm_executor, *,
};

use frame_support::{
    parameter_types,
    traits::{ConstU32, Contains, ContainsPair, Everything, Nothing},
    weights::Weight,
};
use frame_system::EnsureRoot;
use pallet_xcm::XcmPassthrough;
use polkadot_parachain_primitives::primitives::Sibling;
use polkadot_runtime_common::impls::ToAuthor;
use polkadot_sdk::{
    polkadot_sdk_frame::traits::Disabled,
};
use xcm::latest::prelude::*;
use xcm_builder::{
    AccountId32Aliases, AllowExplicitUnpaidExecutionFrom, AllowTopLevelPaidExecutionFrom,
    EnsureXcmOrigin, FixedWeightBounds, FrameTransactionalProcessor, FungibleAdapter, IsConcrete,
    NativeAsset, ParentIsPreset, RelayChainAsNative, SiblingParachainAsNative,
    SiblingParachainConvertsVia, SignedAccountId32AsNative, SignedToAccountId32,
    SovereignSignedViaLocation, TakeWeightCredit, TrailingSetTopicAsId, UsingComponents,
    WithComputedOrigin, WithUniqueTopic,
};
use xcm_executor::XcmExecutor;

parameter_types! {
    pub const RelayLocation: Location = Location::parent();
    pub RelayNativeAssetFilter: (xcm::latest::AssetFilter, xcm::latest::Location) = (
        xcm::latest::AssetFilter::Wild(xcm::latest::WildAsset::AllOf {
            id: xcm::latest::AssetId(xcm::latest::Location::new(1, xcm::latest::Junctions::Here)),
            fun: xcm::latest::WildFungibility::Fungible,
        }),
        xcm::latest::Location::parent(),
    );
    pub const RelayNetwork: Option<NetworkId> = Some(NetworkId::ByGenesis(xcm::latest::WESTEND_GENESIS_HASH));
    pub RelayChainOrigin: RuntimeOrigin = cumulus_pallet_xcm::Origin::Relay.into();
    pub UniversalLocation: InteriorLocation = [
        GlobalConsensus(RelayNetwork::get().unwrap()),
        Parachain(ParachainInfo::parachain_id().into()),
    ].into();
}

pub type LocationToAccountId = (
    ParentIsPreset<AccountId>,
    SiblingParachainConvertsVia<Sibling, AccountId>,
    AccountId32Aliases<RelayNetwork, AccountId>,
);

pub type LocalAssetTransactor = FungibleAdapter<
    Balances,
    IsConcrete<RelayLocation>,
    LocationToAccountId,
    AccountId,
    (),
>;

pub type XcmOriginToTransactDispatchOrigin = (
    SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>,
    RelayChainAsNative<RelayChainOrigin, RuntimeOrigin>,
    SiblingParachainAsNative<cumulus_pallet_xcm::Origin, RuntimeOrigin>,
    SignedAccountId32AsNative<RelayNetwork, RuntimeOrigin>,
    XcmPassthrough<RuntimeOrigin>,
);

parameter_types! {
    pub UnitWeightCost: Weight = Weight::from_parts(1_000_000_000, 64 * 1024);
    pub const MaxInstructions: u32 = 100;
    pub const MaxAssetsIntoHolding: u32 = 64;
}

pub struct ParentOrParentsExecutivePlurality;
impl Contains<Location> for ParentOrParentsExecutivePlurality {
    fn contains(location: &Location) -> bool {
        matches!(location.unpack(), (1, []) | (1, [Plurality { id: BodyId::Executive, .. }]))
    }
}

/// Allow unpaid execution from ProofHub sibling parachains:
/// - para 2000 (quantum ProofHub / distproofhub)
/// - para 2002 (ScanProofHub / Pedersen)
/// These are the only chains authorised to call xcm_record_access_grant.
pub struct ProofHubLocation;
impl Contains<Location> for ProofHubLocation {
    fn contains(location: &Location) -> bool {
        matches!(location.unpack(), (1, [Parachain(2000)]) | (1, [Parachain(2002)]))
    }
}

pub type Barrier = TrailingSetTopicAsId<
    (
        TakeWeightCredit,
        WithComputedOrigin<
            (
                AllowTopLevelPaidExecutionFrom<Everything>,
                AllowExplicitUnpaidExecutionFrom<ParentOrParentsExecutivePlurality>,
                AllowExplicitUnpaidExecutionFrom<ProofHubLocation>,
            ),
            UniversalLocation,
            ConstU32<8>,
        >,
    ),
>;

pub struct AllRelayNativeFromParent;
impl ContainsPair<xcm::latest::Asset, xcm::latest::Location> for AllRelayNativeFromParent {
    fn contains(asset: &xcm::latest::Asset, origin: &xcm::latest::Location) -> bool {
        let relay = xcm::latest::Location::parent();
        *origin == relay &&
            matches!(&asset.id, xcm::latest::AssetId(id) if *id == relay) &&
            matches!(asset.fun, xcm::latest::Fungibility::Fungible(_))
    }
}

pub struct XcmConfig;
impl xcm_executor::Config for XcmConfig {
    type RuntimeCall = RuntimeCall;
    type XcmSender = XcmRouter;
    type XcmEventEmitter = PolkadotXcm;
    type AssetTransactor = LocalAssetTransactor;
    type OriginConverter = XcmOriginToTransactDispatchOrigin;
    type IsReserve = (NativeAsset, AllRelayNativeFromParent);
    type IsTeleporter = ();
    type UniversalLocation = UniversalLocation;
    type Barrier = Barrier;
    type Weigher = FixedWeightBounds<UnitWeightCost, RuntimeCall, MaxInstructions>;
    type Trader =
        UsingComponents<WeightToFee, RelayLocation, AccountId, Balances, ToAuthor<Runtime>>;
    type ResponseHandler = PolkadotXcm;
    type AssetTrap = PolkadotXcm;
    type AssetClaims = PolkadotXcm;
    type SubscriptionService = PolkadotXcm;
    type PalletInstancesInfo = AllPalletsWithSystem;
    type MaxAssetsIntoHolding = MaxAssetsIntoHolding;
    type AssetLocker = ();
    type AssetExchanger = ();
    type FeeManager = ();
    type MessageExporter = ();
    type UniversalAliases = Nothing;
    type CallDispatcher = RuntimeCall;
    type SafeCallFilter = Everything;
    type Aliasers = Nothing;
    type TransactionalProcessor = FrameTransactionalProcessor;
    type HrmpNewChannelOpenRequestHandler = ();
    type HrmpChannelAcceptedHandler = ();
    type HrmpChannelClosingHandler = ();
    type XcmRecorder = PolkadotXcm;
}

pub type XcmRouter = (
    cumulus_primitives_utility::ParentAsUmp<ParachainSystem, PolkadotXcm, ()>,
    XcmpQueue,
);
