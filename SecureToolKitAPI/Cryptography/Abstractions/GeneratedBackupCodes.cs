namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// A generated set of single-use backup codes, with what a caller needs to know to store and enforce
    /// them correctly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every code here is live credential material. They are returned once, are not stored by this API,
    /// and cannot be recovered if lost.
    /// </para>
    /// <para>
    /// A backup code is deliberately weaker than a password: it is short enough to transcribe by hand, so
    /// its safety comes from being single-use and rate-limited rather than from its length. Whatever
    /// accepts these codes must hash them the way it hashes a password, invalidate each on first use, and
    /// limit attempts.
    /// </para>
    /// </remarks>
    public sealed record GeneratedBackupCodes
    {
        /// <summary>The codes, each drawn independently of the others.</summary>
        public required IReadOnlyList<string> Codes { get; init; }

        /// <summary>Characters of randomness in each code, excluding any grouping separators.</summary>
        public required int Length { get; init; }

        /// <summary>Entropy of one code, in bits, rounded to one decimal place.</summary>
        public required double EntropyBitsPerCode { get; init; }

        /// <summary>Plain-language strength of one code.</summary>
        public required string Strength { get; init; }

        /// <summary>What the codes are drawn from, for example <c>digits (10 symbol alphabet)</c>.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about how backup codes must be stored and enforced.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
