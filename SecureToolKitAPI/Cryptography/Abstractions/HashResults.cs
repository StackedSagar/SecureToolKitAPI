namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Result of computing a digest: the digest itself, rendered as asked, together with the figures that let
    /// a caller reproduce it and judge it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nothing here is secret, and that is the point of a hash. A digest is a one-way fingerprint of the
    /// message, not a reversible transformation of it, so it can be published, compared and read out loud
    /// without giving anything about the message away. What this record deliberately does not carry is the
    /// message: the input is the caller's own data and is never echoed back, only counted.
    /// </para>
    /// <para>
    /// <see cref="IsCryptographicallyBroken"/> is reported rather than left for the caller to infer from the
    /// algorithm name, so a caller can refuse a broken digest in code instead of keeping its own list of
    /// which functions have fallen. When it is <c>true</c> the <see cref="Warnings"/> say why and what the
    /// digest may and may not be used for.
    /// </para>
    /// </remarks>
    public sealed record ComputedHash
    {
        /// <summary>
        /// The hash function, spelled as its defining standard spells it, for example <c>SHA-256</c> or
        /// <c>MD5</c>. This is also a value the API accepts as the algorithm to ask for.
        /// </summary>
        public required string Algorithm { get; init; }

        /// <summary>Size of the digest, in bits.</summary>
        public required int DigestSizeBits { get; init; }

        /// <summary>
        /// The digest, rendered according to <see cref="Encoding"/>. Not secret: a digest reveals nothing
        /// about the message it was computed from.
        /// </summary>
        public required string Digest { get; init; }

        /// <summary>How <see cref="Digest"/> is written, for example <c>lowercase hexadecimal</c>.</summary>
        public required string Encoding { get; init; }

        /// <summary>How the message was read before hashing, for example <c>UTF-8 text</c>.</summary>
        public required string InputFormat { get; init; }

        /// <summary>
        /// Number of bytes that were hashed. The message itself is never returned; this is the only thing the
        /// response says about it.
        /// </summary>
        public required int InputByteCount { get; init; }

        /// <summary>
        /// Whether the hash function is cryptographically broken, meaning an attacker can produce two
        /// different messages with the same digest.
        /// </summary>
        public required bool IsCryptographicallyBroken { get; init; }

        /// <summary>
        /// Description of what was hashed and how the result was written, for example
        /// <c>SHA-256 digest of 11 bytes of UTF-8 text, 256 bits written as lowercase hexadecimal (64
        /// characters)</c>. Never contains the message or the digest.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Advisories about what this digest is and is not: that a hash is not encryption, that a fast hash is
        /// not a password store, and — for a broken function — what it may still be used for.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// One entry in the catalogue of hash functions this API will compute. Contains no digest and nothing
    /// that varies between requests.
    /// </summary>
    /// <remarks>
    /// The catalogue exists so a caller can discover the supported functions, their digest sizes and which
    /// are broken, rather than guessing and reading error messages. It carries no caller data and no
    /// secret, which is why it is safe to serve over GET.
    /// </remarks>
    public sealed record HashAlgorithmInfo
    {
        /// <summary>
        /// The function to ask for, spelled as its defining standard spells it, for example <c>SHA-256</c>.
        /// </summary>
        public required string Algorithm { get; init; }

        /// <summary>The function's common name, the same string as <see cref="Algorithm"/>.</summary>
        public required string Name { get; init; }

        /// <summary>Size of the digest this function produces, in bits.</summary>
        public required int DigestSizeBits { get; init; }

        /// <summary>Whether this is the function used when the caller asks for nothing in particular.</summary>
        public required bool IsDefault { get; init; }

        /// <summary>Whether this function is cryptographically broken.</summary>
        public required bool IsCryptographicallyBroken { get; init; }

        /// <summary>What this function is suited to, in plain language.</summary>
        public required string Notes { get; init; }
    }
}
