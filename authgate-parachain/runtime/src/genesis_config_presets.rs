use crate::{
    AccountId, BalancesConfig, CollatorSelectionConfig, ParachainInfoConfig, PolkadotXcmConfig,
    RuntimeGenesisConfig, SessionConfig, SessionKeys, SudoConfig,
    EXISTENTIAL_DEPOSIT,
};

use alloc::{vec, vec::Vec};

use polkadot_sdk::{staging_xcm as xcm, *};

use cumulus_primitives_core::ParaId;
use frame_support::build_struct_json_patch;
use parachains_common::AuraId;
use serde_json::Value;
use sp_genesis_builder::PresetId;
use sp_keyring::Sr25519Keyring;

const SAFE_XCM_VERSION: u32 = xcm::prelude::XCM_VERSION;

/// Para ID for the AuthGate parachain.
pub const PARACHAIN_ID: u32 = 2003;

pub fn authgate_session_keys(keys: AuraId) -> SessionKeys {
    SessionKeys { aura: keys }
}

fn authgate_genesis(
    invulnerables: Vec<(AccountId, AuraId)>,
    endowed_accounts: Vec<AccountId>,
    id: ParaId,
    root_key: AccountId,
) -> Value {
    build_struct_json_patch!(RuntimeGenesisConfig {
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1u128 << 60))
                .collect(),
        },
        parachain_info: ParachainInfoConfig { parachain_id: id, ..Default::default() },
        collator_selection: CollatorSelectionConfig {
            invulnerables: invulnerables.iter().cloned().map(|(acc, _)| acc).collect(),
            candidacy_bond: EXISTENTIAL_DEPOSIT * 16,
            ..Default::default()
        },
        session: SessionConfig {
            keys: invulnerables
                .into_iter()
                .map(|(acc, aura)| {
                    (acc.clone(), acc, authgate_session_keys(aura))
                })
                .collect(),
            ..Default::default()
        },
        polkadot_xcm: PolkadotXcmConfig {
            safe_xcm_version: Some(SAFE_XCM_VERSION),
            ..Default::default()
        },
        sudo: SudoConfig { key: Some(root_key) },
    })
}

fn local_testnet_genesis() -> Value {
    authgate_genesis(
        vec![
            (
                Sr25519Keyring::Alice.to_account_id(),
                Sr25519Keyring::Alice.public().into(),
            ),
            (
                Sr25519Keyring::Bob.to_account_id(),
                Sr25519Keyring::Bob.public().into(),
            ),
        ],
        Sr25519Keyring::well_known().map(|x| x.to_account_id()).collect(),
        PARACHAIN_ID.into(),
        Sr25519Keyring::Alice.to_account_id(),
    )
}

pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::DEV_RUNTIME_PRESET => local_testnet_genesis(),
        sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_testnet_genesis(),
        _ => return None,
    };
    Some(
        serde_json::to_string(&patch)
            .expect("serialization to json is expected to work. qed.")
            .into_bytes(),
    )
}

pub fn preset_names() -> Vec<PresetId> {
    vec![
        PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
        PresetId::from(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET),
    ]
}
