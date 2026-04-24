//! PropChain Test Suite
//!
//! This module provides the test library for PropChain contracts,
//! including shared utilities, fixtures, and test helpers.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod test_utils;

// Include new test modules
#[cfg(test)]
mod property_based_simple;

#[cfg(test)]
mod fuzz_tests_simple;

// Re-export commonly used items
pub use test_utils::*;
