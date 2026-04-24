use soroban_sdk::{Env, Vec, Address};

pub struct Randomness;

impl Randomness {
    /// Generates a random u64 using Soroban's PRNG.
    /// This is secure and deterministic across validators for a given ledger.
    pub fn next_u64(env: &Env, max: u64) -> u64 {
        env.prng().gen_range(0..max)
    }

    /// Selects a random item from a Vec.
    pub fn select_one<T: Clone>(env: &Env, items: Vec<T>) -> Option<T> {
        if items.is_empty() {
            return None;
        }
        let index = env.prng().gen_range(0..items.len());
        Some(items.get(index).unwrap())
    }

    /// Selects multiple unique items from a Vec (e.g., for auditor selection).
    pub fn select_multiple<T: Clone + PartialEq>(env: &Env, items: Vec<T>, count: u32) -> Vec<T> {
        if items.len() <= count {
            return items;
        }

        let mut selected = Vec::new(env);
        let mut available = items;

        for _ in 0..count {
            let index = env.prng().gen_range(0..available.len());
            let item = available.get(index).unwrap();
            selected.push_back(item.clone());
            available.remove(index);
        }

        selected
    }
}
