use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;

#[derive(Clone, Debug)]
pub struct SchedulerStatement {
    pub expected_root: BaseField,
    pub depth: u32,
}

impl SchedulerStatement {
    pub fn new(expected_root: BaseField, depth: u32) -> Self {
        Self { expected_root, depth }
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[self.expected_root.into()]);
        channel.mix_u64(self.depth as u64);
    }
}
