namespace SecureToolKitAPI.Contracts.Hashing
{
    /// <summary>
    /// Options for computing a digest. The message is required; the rest is optional. Omit everything but the
    /// message for a SHA-256 digest of the text as UTF-8, rendered as lowercase hexadecimal.
    /// </summary>
    /// <remarks>
    /// This is the only request contract in the group that names the algorithm. The <c>/sha256</c> and
    /// <c>/md5</c> routes fix the function in the URL and take <see cref="FixedHashRequest"/> instead, which
    /// has no algorithm field to disagree with the route.
    /// </remarks>
    public sealed record HashRequest
    {
        /// <summary>
        /// The hash function: <c>sha256</c>, <c>sha384</c>, <c>sha512</c> or <c>md5</c>. Matching ignores
        /// case, hyphens, underscores and spaces, so <c>SHA-256</c> works too. Defaults to <c>sha256</c>.
        /// <c>sha1</c> and the password-hashing functions are reported as unsupported rather than substituted.
        /// </summary>
        public string? Algorithm { get; init; }

        /// <summary>
        /// How the message is read before hashing: <c>text</c> (UTF-8), <c>base64</c> or <c>hex</c>. Defaults
        /// to <c>text</c>. Use <c>base64</c> or <c>hex</c> to reproduce a checksum computed over a file's raw
        /// bytes.
        /// </summary>
        public string? InputFormat { get; init; }

        /// <summary>
        /// How the digest is written: <c>hex</c> (lowercase), <c>hexupper</c> or <c>base64</c>. Defaults to
        /// <c>hex</c>, which is what <c>sha256sum</c> and <c>md5sum</c> print.
        /// </summary>
        public string? Encoding { get; init; }

        /// <summary>
        /// The message to hash, read according to <see cref="InputFormat"/>. Required; may be empty, which has
        /// a well-defined digest. This is your own data: it is hashed and dropped, never logged and never
        /// echoed back in the response.
        /// </summary>
        public string? Message { get; init; }
    }

    /// <summary>
    /// Options for a route that fixes the hash function in the URL, such as <c>/api/hash/sha256</c> and
    /// <c>/api/hash/md5</c>. Same as <see cref="HashRequest"/> without the algorithm, because the route has
    /// already chosen it.
    /// </summary>
    public sealed record FixedHashRequest
    {
        /// <summary>
        /// How the message is read before hashing: <c>text</c> (UTF-8), <c>base64</c> or <c>hex</c>. Defaults
        /// to <c>text</c>.
        /// </summary>
        public string? InputFormat { get; init; }

        /// <summary>
        /// How the digest is written: <c>hex</c> (lowercase), <c>hexupper</c> or <c>base64</c>. Defaults to
        /// <c>hex</c>.
        /// </summary>
        public string? Encoding { get; init; }

        /// <summary>
        /// The message to hash, read according to <see cref="InputFormat"/>. Required; may be empty. Hashed
        /// and dropped, never logged and never echoed back.
        /// </summary>
        public string? Message { get; init; }
    }

    /// <summary>
    /// A computed digest and the figures that let a caller reproduce it and judge it. Nothing here is secret,
    /// and the message that was hashed is not part of it.
    /// </summary>
    public sealed record HashResponse
    {
        /// <summary>
        /// The hash function, spelled as its standard spells it, for example <c>SHA-256</c>. This is also a
        /// value you can send back as <c>algorithm</c>.
        /// </summary>
        public required string Algorithm { get; init; }

        /// <summary>Size of the digest, in bits.</summary>
        public required int DigestSizeBits { get; init; }

        /// <summary>The digest, rendered as requested. Not secret: it reveals nothing about the message.</summary>
        public required string Digest { get; init; }

        /// <summary>How <see cref="Digest"/> is written, for example <c>lowercase hexadecimal</c>.</summary>
        public required string Encoding { get; init; }

        /// <summary>How the message was read before hashing, for example <c>UTF-8 text</c>.</summary>
        public required string InputFormat { get; init; }

        /// <summary>
        /// Number of bytes that were hashed. The message itself is never returned; this is all the response
        /// says about it.
        /// </summary>
        public required int InputByteCount { get; init; }

        /// <summary>
        /// Whether the function is cryptographically broken. <c>true</c> for MD5; check this in code rather
        /// than keeping your own list of which functions have fallen.
        /// </summary>
        public required bool IsCryptographicallyBroken { get; init; }

        /// <summary>What was hashed and how the result was written. Never contains the message or the digest.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Advisories about what this digest is and is not: that a hash is not encryption, that a fast hash is
        /// not a password store, and — for MD5 — what it may still be used for.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>One hash function this API will compute. Contains no digest and no caller data.</summary>
    public sealed record HashAlgorithmResponse
    {
        /// <summary>The value to send as <c>algorithm</c>, for example <c>SHA-256</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>The function's common name.</summary>
        public required string Name { get; init; }

        /// <summary>Size of the digest this function produces, in bits.</summary>
        public required int DigestSizeBits { get; init; }

        /// <summary>Whether this is the function used when nothing is asked for.</summary>
        public required bool IsDefault { get; init; }

        /// <summary>Whether this function is cryptographically broken.</summary>
        public required bool IsCryptographicallyBroken { get; init; }

        /// <summary>What this function is suited to.</summary>
        public required string Notes { get; init; }
    }
}
