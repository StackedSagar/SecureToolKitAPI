namespace SecureToolKitAPI.Contracts.KeyGeneration
{
    /// <summary>Generated symmetric key or secret.</summary>
    /// <remarks>This response contains secret material. Treat it as sensitive and do not log it.</remarks>
    public sealed record SymmetricKeyResponse
    {
        /// <summary>Algorithm the key was generated for, for example <c>AES-GCM</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Base64 encoded key material.</summary>
        public required string Key { get; init; }

        /// <summary>Key size in bits.</summary>
        public required int KeySize { get; init; }

        /// <summary>Description of the returned key encoding.</summary>
        public required string KeyFormat { get; init; }

        /// <summary>Non-fatal advisories about the generated key.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
