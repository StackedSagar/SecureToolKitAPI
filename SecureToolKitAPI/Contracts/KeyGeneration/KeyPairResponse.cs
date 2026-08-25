namespace SecureToolKitAPI.Contracts.KeyGeneration
{
    /// <summary>Generated asymmetric key pair.</summary>
    /// <remarks>
    /// The private key is secret material. Treat it as sensitive, do not log it and do not share it.
    /// </remarks>
    public sealed record KeyPairResponse
    {
        /// <summary>Algorithm the key pair was generated for, for example <c>RSA-OAEP</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Base64 encoded public key.</summary>
        public required string PublicKey { get; init; }

        /// <summary>Base64 encoded private key.</summary>
        public required string PrivateKey { get; init; }

        /// <summary>Key size in bits, or curve strength for elliptic-curve keys.</summary>
        public required int KeySize { get; init; }

        /// <summary>Description of the returned key encodings.</summary>
        public required string KeyFormat { get; init; }

        /// <summary>Non-fatal advisories about the generated key pair.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
