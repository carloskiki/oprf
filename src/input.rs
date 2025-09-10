/// Input to a OPRF instance.
///
/// This is a byte slice that is less than 2^16 bytes in length. It can be constructed with the
/// `TryFrom<&[u8]>` implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Input<'a>(&'a [u8]);

/// Error indicating that the input is too long.
///
/// This is returned when attempting to create an `Input` from a byte slice with length greater
/// than `u16::MAX` bytes.
pub struct TooLong;

impl<'a> TryFrom<&'a [u8]> for Input<'a> {
    type Error = TooLong;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() > u16::MAX as usize {
            return Err(TooLong);
        }
        Ok(Input(value))
    }
}

impl<'a> AsRef<[u8]> for Input<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> From<Input<'a>> for &'a [u8] {
    fn from(input: Input<'a>) -> Self {
        input.0
    }
}
