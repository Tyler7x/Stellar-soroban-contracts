use soroban_sdk::{contract, contractimpl, Env, Address, Map, symbol_short};

#[derive(Clone)]
pub struct ReinsurancePosition {
    pub reinsurer: Address,
    pub percentage: u32, // 0 - 100
    pub amount: i128,
    pub premium_ceded: i128,
    pub recoverable: i128,
}

fn ceded_positions(e: &Env) -> Map<Address, ReinsurancePosition> {
    e.storage().instance().get(&symbol_short!("CEDES")).unwrap_or(Map::new(e))
}

#[contract]
pub struct ReinsuranceContract;

#[contractimpl]
impl ReinsuranceContract {
    // Cede risk to reinsurer
    pub fn cede_risk(
        env: Env,
        reinsurer: Address,
        percentage: u32,
        amount: i128,
    ) {
        if percentage == 0 || percentage > 100 {
            panic!("Invalid percentage");
        }

        let mut positions = ceded_positions(&env);

        let premium_ceded = amount * percentage as i128 / 100;
        let recoverable = premium_ceded; // simplified

        let position = ReinsurancePosition {
            reinsurer: reinsurer.clone(),
            percentage,
            amount,
            premium_ceded,
            recoverable,
        };

        positions.set(reinsurer.clone(), position);
        env.storage().instance().set(&symbol_short!("CEDES"), &positions);
    }
}

pub fn distribute_payout(env: Env, total_claim: i128) {
    let positions = ceded_positions(&env);

    for (reinsurer, pos) in positions.iter() {
        let share = total_claim * pos.percentage as i128 / 100;

        // call external reinsurer (pseudo)
        env.invoke_contract::<()>(
            &reinsurer,
            &symbol_short!("pay_claim"),
            (share,),
        );
    }
}

pub fn check_reinsurer(env: Env, reinsurer: Address) {
    let approved: bool = env
        .storage()
        .instance()
        .get(&reinsurer)
        .unwrap_or(false);

    if !approved {
        panic!("Reinsurer not approved");
    }
}

pub fn get_total_ceded(env: Env) -> i128 {
    let positions = ceded_positions(&env);

    let mut total: i128 = 0;
    for (_, pos) in positions.iter() {
        total += pos.premium_ceded;
    }
    total
}
