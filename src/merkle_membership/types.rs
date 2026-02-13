use stwo_prover::core::fields::m31::BaseField;

#[derive(Debug, Clone)]
pub struct MerkleInputs {
    pub leaf: BaseField,
    pub siblings: Vec<BaseField>,
    pub index: u32,
    pub expected_root: BaseField,
}

impl MerkleInputs {
    pub fn new(
        leaf: BaseField,
        siblings: Vec<BaseField>,
        index: u32,
        expected_root: BaseField,
    ) -> Self {
        Self {
            leaf,
            siblings,
            index,
            expected_root,
        }
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleOutputs {
    pub computed_root: BaseField,
    pub is_valid: bool,
}

impl MerkleOutputs {
    pub fn new(computed_root: BaseField, expected_root: BaseField) -> Self {
        Self {
            computed_root,
            is_valid: computed_root == expected_root,
        }
    }
}
