namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// A generated recovery key: one value that restores access on its own, written in groups so it can be
    /// read back accurately.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the strongest single credential in an account recovery flow and usually the only one, so it
    /// is sized to resist an offline attack rather than relying on rate limiting. It is returned once, is
    /// not stored by this API, and cannot be recovered if lost.
    /// </para>
    /// <para>
    /// The separators are presentation only. Whatever verifies the key should ignore them and compare the
    /// characters, so a caller who types the key without hyphens is not locked out.
    /// </para>
    /// </remarks>
    public sealed record GeneratedRecoveryKey
    {
        /// <summary>The recovery key, including the group separators.</summary>
        public required string Value { get; init; }

        /// <summary>Characters of randomness, excluding the separators.</summary>
        public required int Characters { get; init; }

        /// <summary>Number of groups the key is written in.</summary>
        public required int Groups { get; init; }

        /// <summary>Entropy of the key, in bits, rounded to one decimal place.</summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language strength of the key.</summary>
        public required string Strength { get; init; }

        /// <summary>What the key is drawn from, and how it is grouped.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about how a recovery key must be stored and verified.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
