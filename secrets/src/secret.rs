use zeroize::Zeroizing;

/// Owned secret bytes. Memory is wiped on drop and the type deliberately does
/// not implement `Debug` / `Display` — leaking through a log line is exactly
/// the kind of accident this wrapper exists to prevent.
///
/// Construct with [`Secret::from_bytes`] or [`Secret::from_string`]. Read with
/// [`Secret::expose`] only at the point of use; do not stash the inner slice
/// in a long-lived field.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wrap raw bytes. The original `Vec` is moved in and zeroized on drop.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Wrap a UTF-8 string. The source `String`'s buffer is consumed; callers
    /// who already hold the bytes should prefer [`Secret::from_bytes`].
    pub fn from_string(s: String) -> Self {
        Self(Zeroizing::new(s.into_bytes()))
    }

    /// Borrow the secret bytes. Hold the borrow for as short a time as possible.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Length in bytes. Useful for backends that need to know the size without
    /// reading the value.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_vec()))
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison would be nicer, but `Secret` is for storage
        // identity — auth flows that need timing-safe compare should pull a
        // dedicated primitive.
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Secret {}
