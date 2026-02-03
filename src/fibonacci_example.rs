use num_traits::{One, Zero};
use stwo::core::fields::qm31::QM31;
use stwo_circuits::{
    circuits::{context::TraceContext, ops::guess},
    eval,
};

pub fn build_fibonacci_circuit(n: usize) -> TraceContext {
    // 1. Stwórz context - to trzyma wszystkie zmienne i gates
    let mut context = TraceContext::default();

    // 2. "Guess" początkowe wartości - prover będzie musiał je podać
    //    guess() tworzy nową zmienną bez constraints
    let mut a = guess(&mut context, QM31::zero()); // F(0) = 0
    let mut b = guess(&mut context, QM31::one()); // F(1) = 1

    // 3. Buduj obwód używając eval! macro
    //    eval! automatycznie dodaje gates (add, mul, etc.)
    for _ in 2..n {
        // F(n+2) = F(n+1) + F(n)
        // eval! tworzy nową zmienną i dodaje constraint
        let c = eval!(&mut context, (a) + (b));
        a = b;
        b = c;
    }

    // 4. Ostatnia wartość (b) to F(n-1)
    println!("F({}) = {:?}", n - 1, context.get(b));

    context
}

#[cfg(test)]
mod tests {
    use stwo_circuits::circuit_prover::prover::prove_circuit;

    use super::*;

    #[test]
    fn test_fibonacci_small() {
        // Test z małą sekwencją
        let mut context = build_fibonacci_circuit(10);

        // Finalizuj guessed vars - dodaje trivial constraints
        context.finalize_guessed_vars();

        // Sprawdź czy circuit jest poprawny
        assert!(context.is_circuit_valid());

        println!("✓ Fibonacci circuit jest poprawny!");
        println!("  Circuit stats: {:?}", context.stats);
    }

    #[test]
    fn test_fibonacci_with_proof() {
        // Buduj circuit z większą sekwencją (musi być power of 2 dla trace)
        let n = 1024;
        let mut context = build_fibonacci_circuit(n);

        // Finalizuj
        context.finalize_guessed_vars();
        context.validate_circuit();

        println!("\n=== Proving Fibonacci circuit ===");
        println!("Sequence length: {}", n);
        println!("Circuit stats: {:?}", context.stats);

        // Prove! To automatycznie:
        // - generuje preprocessed trace
        // - generuje base trace z context.values
        // - generuje interaction trace
        // - wywołuje stwo prove_ex()
        let proof_result = prove_circuit(&mut context);

        // Sprawdź czy proof się udał
        assert!(proof_result.stark_proof.is_ok(), "Proof failed!");

        println!("✓ Proof generated successfully!");
        // Note: CircuitClaim i CircuitInteractionClaim nie mają Debug trait
        // println!("  Claim: {:?}", proof_result.claim);
        // println!("  Interaction claim: {:?}", proof_result.interaction_claim);
    }

    #[test]
    fn test_fibonacci_manual_operations() {
        // Przykład z ręcznymi operacjami (bez eval! macro)
        use stwo_circuits::circuits::ops::add;

        let mut context = TraceContext::default();

        let mut a = guess(&mut context, QM31::zero());
        let mut b = guess(&mut context, QM31::one());

        for _ in 2..20 {
            // Używamy funkcji add() zamiast eval! macro
            let c = add(&mut context, a, b);
            a = b;
            b = c;
        }

        context.finalize_guessed_vars();
        assert!(context.is_circuit_valid());

        println!("✓ Manual operations work!");
    }

    #[test]
    fn test_fibonacci_with_constraints() {
        // Przykład dodawania dodatkowych constraints
        use stwo_circuits::circuits::ops::eq;

        let mut context = TraceContext::default();

        let a0 = guess(&mut context, QM31::zero());
        let a1 = guess(&mut context, QM31::one());

        // Możemy dodać explicit constraint że a0 == 0
        let zero = context.zero();
        let one = context.one();
        eq(&mut context, a0, zero);
        eq(&mut context, a1, one);

        let mut a = a0;
        let mut b = a1;

        for _ in 2..10 {
            let c = eval!(&mut context, (a) + (b));
            a = b;
            b = c;
        }

        context.finalize_guessed_vars();
        assert!(context.is_circuit_valid());

        println!("✓ Circuit with explicit constraints works!");
    }
}
