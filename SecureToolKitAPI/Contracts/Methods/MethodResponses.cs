namespace SecureToolKitAPI.Contracts.Methods
{
    /// <summary>Describes a supported key-generation method.</summary>
    public sealed record KeyGenerationMethodResponse
    {
        /// <summary>Canonical method identifier.</summary>
        public required string Name { get; init; }

        /// <summary>Alternative identifiers accepted for this method, matched case-insensitively.</summary>
        public required IReadOnlyCollection<string> Aliases { get; init; }

        /// <summary>What the method generates.</summary>
        public required string Description { get; init; }

        /// <summary>Accepted key sizes in bits.</summary>
        public required IReadOnlyCollection<int> SupportedKeySizes { get; init; }

        /// <summary>Key size used when the caller does not specify one.</summary>
        public required int DefaultKeySize { get; init; }
    }

    /// <summary>Describes a supported encryption/decryption method.</summary>
    public sealed record EncryptionMethodResponse
    {
        /// <summary>Canonical method identifier, used as the <c>{method}</c> route segment.</summary>
        public required string Name { get; init; }

        /// <summary>Alternative identifiers accepted for this method, matched case-insensitively.</summary>
        public required IReadOnlyCollection<string> Aliases { get; init; }

        /// <summary>What the method does.</summary>
        public required string Description { get; init; }

        /// <summary>Key material the method expects.</summary>
        public required string KeyFormat { get; init; }

        /// <summary>Documented byte layout of the envelope the method produces and consumes.</summary>
        public required string EnvelopeLayout { get; init; }
    }

    /// <summary>Describes a supported signature method.</summary>
    public sealed record SignatureMethodResponse
    {
        /// <summary>Canonical method identifier, used as the <c>{method}</c> route segment.</summary>
        public required string Name { get; init; }

        /// <summary>Alternative identifiers accepted for this method, matched case-insensitively.</summary>
        public required IReadOnlyCollection<string> Aliases { get; init; }

        /// <summary>What the method does.</summary>
        public required string Description { get; init; }

        /// <summary>Key material used for signing.</summary>
        public required string SigningKeyFormat { get; init; }

        /// <summary>Key material used for verification.</summary>
        public required string VerificationKeyFormat { get; init; }

        /// <summary>Encoding of the produced signature.</summary>
        public required string SignatureFormat { get; init; }
    }
}
