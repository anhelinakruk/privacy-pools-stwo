use stwo_prover::core::{channel::Channel, fields::m31::BaseField};

#[derive(Clone, Debug)]
pub struct SchedulerStatement {
    pub expected_root: BaseField,
    pub depth: u32,
    pub nullifier: BaseField,
    pub token_address: BaseField,
    pub amount: BaseField,
    pub refund_commitment_hash: BaseField,
    pub recipient: BaseField,
}

impl SchedulerStatement {
    pub fn new(
        expected_root: BaseField,
        depth: u32,
        nullifier: BaseField,
        token_address: BaseField,
        amount: BaseField,
        refund_commitment_hash: BaseField,
        recipient: BaseField,
    ) -> Self {
        Self {
            expected_root,
            depth,
            nullifier,
            token_address,
            amount,
            refund_commitment_hash,
            recipient,
        }
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[
            self.expected_root.into(),
            self.nullifier.into(),
            self.token_address.into(),
            self.amount.into(),
            self.refund_commitment_hash.into(),
            self.recipient.into(),
        ]);
        channel.mix_u64(self.depth as u64);
    }
}
