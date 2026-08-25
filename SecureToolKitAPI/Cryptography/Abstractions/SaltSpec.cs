namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Options for a generated salt: how many random bytes it carries and how they are written down.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A salt is sized in bytes rather than bits because that is how every password-hashing API takes it,
    /// and because the value is stored next to the hash it belongs to rather than configured as a key.
    /// </para>
    /// <para>
    /// The encoding must be a byte encoding, so the exact bytes can be recovered when a hash is verified.
    /// <see cref="SecretEncoding.Base62"/> samples characters rather than re-basing bytes, so it cannot
    /// represent a salt and is rejected.
    /// </para>
    /// </remarks>
    public sealed record SaltSpec
    {
        /// <summary>Fewest random bytes this API will generate for a salt, 64 bits.</summary>
        /// <remarks>RFC 8018 requires a PBKDF2 salt of at least eight octets.</remarks>
        public const int MinimumBytes = 8;

        /// <summary>Most random bytes this API will generate for a salt, 512 bits.</summary>
        public const int MaximumBytes = 64;

        /// <summary>
        /// Bytes of randomness. Between 8 and 64; defaults to 16, or 128 bits, which is the size the
        /// current password-hashing algorithms are specified and tuned for.
        /// </summary>
        public int Bytes { get; init; } = 16;

        /// <summary>
        /// How the random bytes are written down. Defaults to <see cref="SecretEncoding.Base64"/>, which
        /// is the form stored password hashes usually carry their salt in.
        /// </summary>
        public SecretEncoding Encoding { get; init; } = SecretEncoding.Base64;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            if (Bytes is < MinimumBytes or > MaximumBytes)
            {
                throw new CryptographicRequestException(
                    $"The salt size must be between {MinimumBytes} and {MaximumBytes} bytes.");
            }

            if (!Enum.IsDefined(Encoding))
            {
                throw new CryptographicRequestException("The requested encoding is not supported.");
            }

            // Rejected rather than quietly substituted: a salt that cannot be decoded back to the bytes it
            // was generated from cannot be used to verify the hash it was generated for.
            if (Encoding == SecretEncoding.Base62)
            {
                throw new CryptographicRequestException(
                    "Base62 is not a byte encoding, so it cannot represent a salt. "
                    + "Supported values: Base64, Base64Url, Hex, HexUpper.");
            }
        }
    }
}
