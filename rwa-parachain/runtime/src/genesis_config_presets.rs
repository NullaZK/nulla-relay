use crate::{
    AccountId, BalancesConfig, CollatorSelectionConfig, ParachainInfoConfig, PolkadotXcmConfig,
    RwaRegistryConfig, RuntimeGenesisConfig, SessionConfig, SessionKeys, SudoConfig,
    EXISTENTIAL_DEPOSIT,
};

use alloc::{vec, vec::Vec};

use polkadot_sdk::{staging_xcm as xcm, *};

use cumulus_primitives_core::ParaId;
use frame_support::build_struct_json_patch;
use parachains_common::AuraId;
use pallet_rwa_registry::pallet::{
    AssetCategory, CompanyInfo, RWAAsset, MAX_DISCLAIMER_LEN, MAX_DESC_LEN, MAX_INFO_STR_LEN,
    MAX_META_LEN, MAX_NAME_LEN,
};
use serde_json::Value;
use sp_genesis_builder::PresetId;
use sp_keyring::Sr25519Keyring;

const SAFE_XCM_VERSION: u32 = xcm::prelude::XCM_VERSION;

/// Para ID for the RWA appchain.
pub const PARACHAIN_ID: u32 = 2001;

pub fn rwa_session_keys(keys: AuraId) -> SessionKeys {
    SessionKeys { aura: keys }
}

// ── Helper macros ─────────────────────────────────────────────────────────

macro_rules! bvec {
    ($s:expr, $max:ty) => {{
        let bytes: &[u8] = $s.as_bytes();
        BoundedVec::<u8, $max>::try_from(bytes.to_vec()).expect("string fits bound")
    }};
}

use frame_support::traits::ConstU32;
use sp_runtime::BoundedVec;

// ── 20 demo assets ───────────────────────────────────────────────────────

fn demo_assets(admin: AccountId) -> Vec<RWAAsset<AccountId>> {
    vec![
        // ── Real Estate (5) ────────────────────────────────────────────────
        RWAAsset {
            asset_id: 0,
            name: bvec!("Office Tower Berlin", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Prime 18-floor office tower in Mitte, Berlin, fully leased to tech tenants.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::RealEstate,
            usd_value_cents: 240_000_000_00, // €2.4M in cents
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"location\":\"Berlin,DE\",\"sqm\":4200,\"floors\":18}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 1,
            name: bvec!("Residential Complex Prague", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "48-unit residential complex in Vinohrady, Prague, 95% occupancy.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::RealEstate,
            usd_value_cents: 89_000_000_00, // €890k
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"location\":\"Prague,CZ\",\"units\":48}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 2,
            name: bvec!("Warehouse Rotterdam Port", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "12,000 sqm logistics warehouse adjacent to Rotterdam Europort.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::RealEstate,
            usd_value_cents: 120_000_000_00, // €1.2M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"location\":\"Rotterdam,NL\",\"sqm\":12000}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 3,
            name: bvec!("Retail Mall Madrid", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Regional retail mall in northern Madrid suburbs, 120 tenants.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::RealEstate,
            usd_value_cents: 510_000_000_00, // €5.1M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"location\":\"Madrid,ES\",\"tenants\":120}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 4,
            name: bvec!("Hotel Property Lisbon", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "4-star boutique hotel in historic Alfama district, Lisbon, 85 rooms.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::RealEstate,
            usd_value_cents: 370_000_000_00, // €3.7M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"location\":\"Lisbon,PT\",\"rooms\":85,\"stars\":4}", ConstU32::<{ MAX_META_LEN }>),
        },
        // ── Fleet (5) ────────────────────────────────────────────────
        RWAAsset {
            asset_id: 5,
            name: bvec!("Cargo Ship Hull RX-7721", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Panamax bulk carrier, IMO 9812345, 76,000 DWT, built 2019, flagged Malta.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Fleet,
            usd_value_cents: 830_000_000_00, // €8.3M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"imo\":\"9812345\",\"dwt\":76000,\"flag\":\"MT\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 6,
            name: bvec!("European Truck Fleet 50 Units", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "50 x Mercedes-Benz Actros 2021 long-haul trucks, EUR 6 compliant.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Fleet,
            usd_value_cents: 450_000_000_00, // €4.5M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"make\":\"Mercedes-Benz\",\"model\":\"Actros\",\"count\":50,\"year\":2021}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 7,
            name: bvec!("Mining Equipment Set", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Caterpillar 336 excavator fleet of 6 units, currently contracted in Poland.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Fleet,
            usd_value_cents: 210_000_000_00, // €2.1M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"make\":\"Caterpillar\",\"model\":\"336\",\"count\":6}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 8,
            name: bvec!("Solar Farm Array 100MW", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "100 MW photovoltaic installation in Andalusia, Spain, grid-connected.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Fleet,
            usd_value_cents: 620_000_000_00, // €6.2M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"location\":\"Andalusia,ES\",\"capacity_mw\":100,\"type\":\"PV\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 9,
            name: bvec!("Agriculture Machinery Pool", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Pool of 12 John Deere combine harvesters leased to Ukrainian cooperatives.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Fleet,
            usd_value_cents: 98_000_000_00, // €980k
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"make\":\"John Deere\",\"type\":\"combine\",\"count\":12}", ConstU32::<{ MAX_META_LEN }>),
        },
        // ── Financial Instruments (5) ─────────────────────────────────
        RWAAsset {
            asset_id: 10,
            name: bvec!("Trade Finance Receivable A", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Batch-A trade receivables from 10 exporters across MENA, 90-day maturity.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::FinancialInstrument,
            usd_value_cents: 50_000_000_00, // €500k
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"batch\":\"A\",\"borrowers\":10,\"maturity_days\":90}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 11,
            name: bvec!("Supply Chain Invoice Pool", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Diversified invoice pool from 25 EU mid-cap suppliers, average 60-day terms.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::FinancialInstrument,
            usd_value_cents: 110_000_000_00, // €1.1M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"suppliers\":25,\"avg_days\":60,\"region\":\"EU\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 12,
            name: bvec!("Corporate Bond Series 2026", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "5% coupon corporate bond maturing 2026, issued by NullaFinance AG, ISIN XS0000000001.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::FinancialInstrument,
            usd_value_cents: 1_000_000_000_00, // €10M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"isin\":\"XS0000000001\",\"coupon\":\"5%\",\"maturity\":\"2026\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 13,
            name: bvec!("Infrastructure Revenue Share", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "15-year revenue share agreement on toll road A8 extension, Bavaria.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::FinancialInstrument,
            usd_value_cents: 320_000_000_00, // €3.2M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"type\":\"revenue_share\",\"road\":\"A8\",\"years\":15}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 14,
            name: bvec!("Export Credit Note Series-1", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Export credit note backed by ECA guarantee, covering machinery exports to Africa.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::FinancialInstrument,
            usd_value_cents: 75_000_000_00, // €750k
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"type\":\"export_credit\",\"eca\":\"EKF\",\"tenor_months\":24}", ConstU32::<{ MAX_META_LEN }>),
        },
        // ── IP & Commodities (5) ──────────────────────────────────────
        RWAAsset {
            asset_id: 15,
            name: bvec!("Patent Portfolio Biotech", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "12 patents in mRNA delivery and lipid nanoparticle synthesis, licensed to 3 pharma firms.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::IntellectualProperty,
            usd_value_cents: 280_000_000_00, // €2.8M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"patents\":12,\"domain\":\"mRNA\",\"licensees\":3}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 16,
            name: bvec!("Carbon Credit Pool 50k tCO2", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "50,000 verified carbon credits (VCS) from reforestation projects in Brazil.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Commodity,
            usd_value_cents: 140_000_000_00, // €1.4M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"standard\":\"VCS\",\"tco2\":50000,\"origin\":\"BR\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 17,
            name: bvec!("Gold Reserve 100kg", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "100 kg of LBMA-certified 99.99% fine gold bars stored in Zurich vault.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Commodity,
            usd_value_cents: 590_000_000_00, // €5.9M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"purity\":\"99.99%\",\"weight_kg\":100,\"vault\":\"Zurich\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 18,
            name: bvec!("Software License Bundle", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Enterprise perpetual licenses for 3 SaaS products with 800+ active business seats.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::IntellectualProperty,
            usd_value_cents: 65_000_000_00, // €650k
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"products\":3,\"seats\":800,\"type\":\"perpetual\"}", ConstU32::<{ MAX_META_LEN }>),
        },
        RWAAsset {
            asset_id: 19,
            name: bvec!("Art Collection Euro Masters", ConstU32::<{ MAX_NAME_LEN }>),
            description: bvec!(
                "Curated collection of 8 European masters artworks, provenance verified, insured.",
                ConstU32::<{ MAX_DESC_LEN }>
            ),
            category: AssetCategory::Commodity,
            usd_value_cents: 420_000_000_00, // €4.2M
            owner: admin.clone(),
            is_locked: true,
            is_sold: false,
            metadata: bvec!("{\"pieces\":8,\"insured\":true,\"provenance\":\"verified\"}", ConstU32::<{ MAX_META_LEN }>),
        },
    ]
}

fn testnet_genesis(
    invulnerables: Vec<(AccountId, AuraId)>,
    endowed_accounts: Vec<AccountId>,
    root: AccountId,
    id: ParaId,
) -> Value {
    let admin = root.clone();
    let assets = demo_assets(admin.clone());

    build_struct_json_patch!(RuntimeGenesisConfig {
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1u128 << 60))
                .collect::<Vec<_>>(),
        },
        parachain_info: ParachainInfoConfig { parachain_id: id },
        collator_selection: CollatorSelectionConfig {
            invulnerables: invulnerables.iter().cloned().map(|(acc, _)| acc).collect::<Vec<_>>(),
            candidacy_bond: EXISTENTIAL_DEPOSIT * 16,
        },
        session: SessionConfig {
            keys: invulnerables
                .into_iter()
                .map(|(acc, aura)| (acc.clone(), acc, rwa_session_keys(aura)))
                .collect::<Vec<_>>(),
        },
        polkadot_xcm: PolkadotXcmConfig { safe_xcm_version: Some(SAFE_XCM_VERSION) },
        sudo: SudoConfig { key: Some(root) },
        rwa_registry: RwaRegistryConfig {
            assets,
            company: Some(CompanyInfo {
                name: bvec!("Nulla RWA Company (Demo)", ConstU32::<{ MAX_INFO_STR_LEN }>),
                disclaimer: bvec!(
                    "This parachain is independently operated for demonstration purposes only. \
                     Nulla developers assume no liability for the assets listed herein. \
                     Do not use with real funds.",
                    ConstU32::<{ MAX_DISCLAIMER_LEN }>
                ),
            }),
        },
    })
}

fn local_testnet_genesis() -> Value {
    testnet_genesis(
        vec![
            (Sr25519Keyring::Alice.to_account_id(), Sr25519Keyring::Alice.public().into()),
            (Sr25519Keyring::Bob.to_account_id(), Sr25519Keyring::Bob.public().into()),
        ],
        Sr25519Keyring::well_known().map(|k| k.to_account_id()).collect(),
        Sr25519Keyring::Alice.to_account_id(),
        PARACHAIN_ID.into(),
    )
}

fn development_config_genesis() -> Value {
    testnet_genesis(
        vec![
            (Sr25519Keyring::Alice.to_account_id(), Sr25519Keyring::Alice.public().into()),
            (Sr25519Keyring::Bob.to_account_id(), Sr25519Keyring::Bob.public().into()),
        ],
        Sr25519Keyring::well_known().map(|k| k.to_account_id()).collect(),
        Sr25519Keyring::Alice.to_account_id(),
        PARACHAIN_ID.into(),
    )
}

pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_testnet_genesis(),
        sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
        _ => return None,
    };
    Some(
        serde_json::to_string(&patch)
            .expect("serialization to json is expected to work. qed.")
            .into_bytes(),
    )
}
