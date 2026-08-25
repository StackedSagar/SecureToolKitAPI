namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Result of a key-generation operation. Symmetric methods populate <see cref="Key"/>;
    /// asymmetric methods populate <see cref="PublicKey"/> and <see cref="PrivateKey"/>.
    /// </summary>
    /// <remarks>
    /// Instances contain secret material and must never be logged.
    /// </remarks>
    public sealed record GeneratedKey
    {
        /// <summary>Algorithm label reported to the caller, for example <c>AES-GCM</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Effective key size in bits.</summary>
        public required int KeySizeBits { get; init; }

        /// <summary>Base64 symmetric key or secret, when the method is symmetric.</summary>
        public string? Key { get; init; }

        /// <summary>Base64 public key, when the method is asymmetric.</summary>
        public string? PublicKey { get; init; }

        /// <summary>Base64 private key, when the method is asymmetric.</summary>
        public string? PrivateKey { get; init; }

        /// <summary>Description of the encoding/format of the returned key material.</summary>
        public required string KeyFormat { get; init; }

        /// <summary>Non-fatal advisories, for example that a requested key size is deprecated.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
