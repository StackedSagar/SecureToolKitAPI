namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// A generated salt: random bytes that make an input unique before it is hashed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unlike the other values this API produces, a salt is not a secret. Its job is uniqueness, not
    /// confidentiality: it stops two identical inputs producing the same hash, which is what makes
    /// precomputed tables and cross-account comparisons work. It is stored alongside the hash by design.
    /// </para>
    /// <para>
    /// A salt is not a substitute for a password-hashing function, and hashing is not encryption. A salted
    /// hash cannot be reversed to recover the input, by anyone, including whoever created it.
    /// </para>
    /// </remarks>
    public sealed record GeneratedSalt
    {
        /// <summary>The salt, written in the requested encoding.</summary>
        public required string Value { get; init; }

        /// <summary>Number of random bytes behind <see cref="Value"/>.</summary>
        public required int Bytes { get; init; }

        /// <summary>How <see cref="Value"/> is encoded, so a caller knows what to decode.</summary>
        public required string Format { get; init; }

        /// <summary>Advisories about how a salt must be used.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
