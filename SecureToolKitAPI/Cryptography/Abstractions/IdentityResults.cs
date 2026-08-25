namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>Result of generating a batch of UUIDs.</summary>
    /// <remarks>
    /// A UUID is an identifier rather than a credential. Every value here is drawn from a cryptographically
    /// secure generator, so a version 4 value is unpredictable, but these are routinely logged, put in URLs
    /// and printed — <see cref="Warnings"/> says so, so nobody reaches for one as a bearer token.
    /// </remarks>
    public sealed record GeneratedUuids
    {
        /// <summary>The generated identifiers, in the requested format.</summary>
        public required IReadOnlyList<string> Values { get; init; }

        /// <summary>The version that was generated, for example <c>v4</c>.</summary>
        public required string Version { get; init; }

        /// <summary>How the values are written, for example <c>hyphenated</c>.</summary>
        public required string Format { get; init; }

        /// <summary>Random bits in one value: 122 for version 4, 74 for version 7.</summary>
        public required int RandomBits { get; init; }

        /// <summary>Description of the layout. Never contains a generated value.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about what these values are and are not suitable for.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>Result of generating a TOTP shared secret.</summary>
    /// <remarks>
    /// <see cref="Secret"/> is the whole of the second factor: whoever holds it can produce valid codes for
    /// as long as the enrollment lasts. It must never be logged, and it is shown to the person enrolling
    /// exactly once.
    /// </remarks>
    public sealed record GeneratedTotpSecret
    {
        /// <summary>The shared secret, Base32 encoded as authenticators expect. Secret.</summary>
        public required string Secret { get; init; }

        /// <summary>Number of random bytes behind <see cref="Secret"/>.</summary>
        public required int Bytes { get; init; }

        /// <summary>Entropy of the secret in bits, which is eight per random byte.</summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>The hash function the secret is sized for, as an <c>otpauth</c> URI writes it.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Digits in a code produced from this secret.</summary>
        public required int Digits { get; init; }

        /// <summary>Seconds each code is valid for.</summary>
        public required int PeriodSeconds { get; init; }

        /// <summary>How the secret was built and what it will be used with. Never contains the secret.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about how the secret must be stored and enrolled.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// Result of building a complete TOTP enrollment: the shared secret and the <c>otpauth</c> URI an
    /// authenticator application reads from a QR code.
    /// </summary>
    /// <remarks>
    /// Both <see cref="Secret"/> and <see cref="Uri"/> are secret material — the URI contains the secret,
    /// so a QR code rendered from it is a picture of the second factor and must be treated as one.
    /// </remarks>
    public sealed record TotpEnrollment
    {
        /// <summary>The shared secret, Base32 encoded, for a person entering it by hand. Secret.</summary>
        public required string Secret { get; init; }

        /// <summary>
        /// The <c>otpauth://totp/</c> URI, for a QR code. Contains the secret, so it is exactly as
        /// sensitive as <see cref="Secret"/>.
        /// </summary>
        public required string Uri { get; init; }

        /// <summary>The service the enrollment is for, as it will appear in the authenticator.</summary>
        public required string Issuer { get; init; }

        /// <summary>The account the enrollment is for, as it will appear in the authenticator.</summary>
        public required string Account { get; init; }

        /// <summary>The hash function, as the URI writes it.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Digits in a code.</summary>
        public required int Digits { get; init; }

        /// <summary>Seconds each code is valid for.</summary>
        public required int PeriodSeconds { get; init; }

        /// <summary>Number of bytes the secret decodes to.</summary>
        public required int Bytes { get; init; }

        /// <summary>Description of the enrollment. Never contains the secret.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about how the enrollment must be delivered and stored.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>Result of computing a TOTP code.</summary>
    /// <remarks>
    /// The code itself is short-lived and low-value, but it was computed from a secret the caller supplied,
    /// and nothing here echoes that secret back.
    /// </remarks>
    public sealed record TotpCode
    {
        /// <summary>The code, zero-padded to the requested number of digits.</summary>
        public required string Code { get; init; }

        /// <summary>Unix time in seconds the code was computed for.</summary>
        public required long UnixTimeSeconds { get; init; }

        /// <summary>The RFC 6238 counter: the time divided by the period.</summary>
        public required long Counter { get; init; }

        /// <summary>Seconds remaining before this code is replaced by the next one.</summary>
        public required int ValidForSeconds { get; init; }

        /// <summary>The hash function used.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Digits in the code.</summary>
        public required int Digits { get; init; }

        /// <summary>Seconds each code is valid for.</summary>
        public required int PeriodSeconds { get; init; }

        /// <summary>Description of how the code was computed. Never contains the secret.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about what this result is and is not.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>Result of re-rendering bytes in another encoding.</summary>
    /// <remarks>
    /// Encoding is not encryption: the result is reversible by anyone and protects nothing. It is exactly
    /// as sensitive as the input it was produced from, which is why <see cref="Warnings"/> says so on every
    /// response rather than only on some.
    /// </remarks>
    public sealed record EncodedText
    {
        /// <summary>The encoded value.</summary>
        public required string Value { get; init; }

        /// <summary>The encoding that was applied, for example <c>Base32 (RFC 4648)</c>.</summary>
        public required string Encoding { get; init; }

        /// <summary>Number of bytes that were encoded.</summary>
        public required int Bytes { get; init; }

        /// <summary>Number of characters in <see cref="Value"/>.</summary>
        public required int Length { get; init; }

        /// <summary>Description of what was done. Never contains the input.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories, always including that this is an encoding rather than encryption.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
