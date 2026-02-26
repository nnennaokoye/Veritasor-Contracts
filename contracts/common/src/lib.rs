#![cfg_attr(not(test), no_std)]
//! Shared utilities and security invariant tests for Veritasor contracts.

pub mod merkle;

#[cfg(test)]
pub mod merkle_test;

pub mod governance_gating;
pub mod key_rotation;

#[cfg(test)]
pub mod interface_spec_check;

#[cfg(test)]
pub mod interface_spec_check_test;

#[cfg(test)]
pub mod key_rotation_test;

#[cfg(test)]
pub mod merkle_fuzz_test;

#[cfg(test)]
pub mod security_invariant_test;
