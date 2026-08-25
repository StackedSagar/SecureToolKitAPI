namespace SecureToolKitAPI.Contracts.Identity
{
    /// <summary>
    /// Options for a batch of UUIDs. Every member is optional; omit the body entirely to accept the
    /// defaults, which are one lowercase hyphenated version 4 identifier.
    /// </summary>
    /// <remarks>
    /// Values outside the documented ranges are reported as a 400 problem response rather than being
    /// clamped silently.
    /// </remarks>
    public sealed record UuidRequest
    {
        /// <summary>How many to generate. Between 1 and 100; defaults to 1.</summary>
        public int? Count { get; init; }

        /// <summary>
        /// Which layout: <c>v4</c> for 122 random bits, or <c>v7</c> for a timestamp followed by 74 random
        /// bits so the values sort in creation order. Defaults to <c>v4</c>.
        /// </summary>
        public string? Version { get; init; }

        /// <summary>
        /// How to write them: <c>hyphenated</c>, <c>compact</c>, <c>braced</c> or <c>urn</c>. Defaults to
        /// <c>hyphenated</c>.
        /// </summary>
        public string? Format { get; init; }

        /// <summary>
        /// Write the hexadecimal digits in uppercase. Defaults to <c>false</c>; RFC 9562 requires lowercase
        /// on output.
        /// </summary>
        public bool? Uppercase { get; init; }
    }

    /// <summary>
    /// Options for a TOTP shared secret. Every member is optional; omit the body entirely for a 160-bit
    /// SHA-1 secret with six digit codes on a 30 second step, which is what every authenticator supports.
    /// </summary>
    public sealed record TotpSecretRequest
    {
        /// <summary>
        /// Bytes of randomness. Between 16 and 64; omit for the size recommended for the algorithm, which
        /// is 20 bytes for SHA-1.
        /// </summary>
        public int? Bytes { get; init; }

        /// <summary>
        /// Which hash function: <c>SHA1</c>, <c>SHA256</c> or <c>SHA512</c>. Defaults to <c>SHA1</c>, the
        /// only one every authenticator implements.
        /// </summary>
        public string? Algorithm { get; init; }

        /// <summary>Digits in a code. Between 6 and 8; defaults to 6.</summary>
        public int? Digits { get; init; }

        /// <summary>Seconds each code is valid for. Between 15 and 300; defaults to 30.</summary>
        public int? PeriodSeconds { get; init; }
    }

    /// <summary>
    /// A complete TOTP enrollment: the issuer and account the person will see in their authenticator, and
    /// optionally an existing secret to build the URI around.
    /// </summary>
    /// <remarks>
    /// The issuer and account are required, because an authenticator entry labelled with neither cannot be
    /// told apart from the others. Supply <see cref="Secret"/> only when re-issuing the URI for a secret
    /// that already exists; omit it to have one generated.
    /// </remarks>
    public sealed record TotpEnrollmentRequest
    {
        /// <summary>
        /// The service the code is for, as the person will see it. Required, at most 64 characters, and no
        /// colon.
        /// </summary>
        public string? Issuer { get; init; }

        /// <summary>
        /// Who the code belongs to, usually an email address or user name. Required, at most 64 characters,
        /// and no colon.
        /// </summary>
        public string? Account { get; init; }

        /// <summary>
        /// An existing Base32 secret. Omit to generate a new one. Cannot be combined with
        /// <see cref="Bytes"/>.
        /// </summary>
        public string? Secret { get; init; }

        /// <summary>
        /// Bytes of randomness for a generated secret. Between 16 and 64; ignored, and refused, when
        /// <see cref="Secret"/> is supplied.
        /// </summary>
        public int? Bytes { get; init; }

        /// <summary>Which hash function: <c>SHA1</c>, <c>SHA256</c> or <c>SHA512</c>. Defaults to <c>SHA1</c>.</summary>
        public string? Algorithm { get; init; }

        /// <summary>Digits in a code. Between 6 and 8; defaults to 6.</summary>
        public int? Digits { get; init; }

        /// <summary>Seconds each code is valid for. Between 15 and 300; defaults to 30.</summary>
        public int? PeriodSeconds { get; init; }
    }

    /// <summary>The secret to compute a code from, and the parameters it was enrolled with.</summary>
    /// <remarks>
    /// <para>
    /// The secret travels in the request body and only in the request body, because a query string ends up
    /// in server logs, proxy logs and browser history. This API does not log it, store it or return it.
    /// </para>
    /// <para>
    /// This computes a code; it verifies nothing. Sending a live TOTP secret to any service — including
    /// this one — is a decision worth making deliberately.
    /// </para>
    /// </remarks>
    public sealed record TotpCodeRequest
    {
        /// <summary>
        /// The shared secret, Base32 encoded. Required. Hyphens, spaces, lowercase and missing padding are
        /// all accepted.
        /// </summary>
        public string? Secret { get; init; }

        /// <summary>Which hash function the secret was enrolled with. Defaults to <c>SHA1</c>.</summary>
        public string? Algorithm { get; init; }

        /// <summary>Digits in the code. Between 6 and 8; defaults to 6.</summary>
        public int? Digits { get; init; }

        /// <summary>Seconds each code is valid for. Between 15 and 300; defaults to 30.</summary>
        public int? PeriodSeconds { get; init; }

        /// <summary>
        /// Unix time in seconds to compute the code for. Omit for now, which is what checking an enrollment
        /// against a person's authenticator needs.
        /// </summary>
        public long? UnixTimeSeconds { get; init; }
    }

    /// <summary>The bytes to render as Base32, given either as text or as Base64.</summary>
    /// <remarks>
    /// Supply exactly one of <see cref="Text"/> and <see cref="Base64"/>. Base32 is an encoding, not
    /// encryption: the result protects nothing and is exactly as sensitive as the input.
    /// </remarks>
    public sealed record Base32Request
    {
        /// <summary>Text to encode, taken as UTF-8. At most 4096 bytes once encoded.</summary>
        public string? Text { get; init; }

        /// <summary>Bytes to encode, given as Base64, for input that is not text. At most 4096 bytes.</summary>
        public string? Base64 { get; init; }

        /// <summary>
        /// Pad the result to a whole eight-character block with <c>=</c>. Defaults to <c>true</c>; an
        /// <c>otpauth</c> URI omits the padding.
        /// </summary>
        public bool? Padding { get; init; }

        /// <summary>Write the result in lowercase. Defaults to <c>false</c>.</summary>
        public bool? Lowercase { get; init; }
    }

    /// <summary>Generated UUIDs.</summary>
    /// <remarks>
    /// These are identifiers rather than credentials. They are drawn from a cryptographically secure
    /// generator, but they are meant to be logged and printed — see <see cref="Warnings"/>.
    /// </remarks>
    public sealed record UuidResponse
    {
        /// <summary>The identifiers, in the requested format.</summary>
        public required IReadOnlyList<string> Values { get; init; }

        /// <summary>How many were generated.</summary>
        public required int Count { get; init; }

        /// <summary>The version that was generated.</summary>
        public required string Version { get; init; }

        /// <summary>How the values are written.</summary>
        public required string Format { get; init; }

        /// <summary>Random bits in one value: 122 for version 4, 74 for version 7.</summary>
        public required int RandomBits { get; init; }

        /// <summary>What the layout consists of. Never contains a generated value.</summary>
        public required string Composition { get; init; }

        /// <summary>What these values are, and are not, suitable for.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>A generated TOTP shared secret.</summary>
    /// <remarks>
    /// The secret is the entire second factor, returned once and not stored by this API. Do not log this
    /// response, do not cache it and do not put the secret in a URL.
    /// </remarks>
    public sealed record TotpSecretResponse
    {
        /// <summary>The shared secret, Base32 encoded without padding, as authenticators expect.</summary>
        public required string Secret { get; init; }

        /// <summary>Bytes of randomness behind the secret.</summary>
        public required int Bytes { get; init; }

        /// <summary>Entropy of the secret, in bits.</summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>The hash function the secret is sized for.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Digits in a code produced from this secret.</summary>
        public required int Digits { get; init; }

        /// <summary>Seconds each code is valid for.</summary>
        public required int PeriodSeconds { get; init; }

        /// <summary>What the secret was built from. Never contains the secret.</summary>
        public required string Composition { get; init; }

        /// <summary>How the secret must be enrolled, stored and verified against.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>A TOTP enrollment, ready to be turned into a QR code.</summary>
    /// <remarks>
    /// Both the secret and the URI are live credential material — the URI contains the secret, so a QR code
    /// rendered from it is a picture of the second factor.
    /// </remarks>
    public sealed record TotpEnrollmentResponse
    {
        /// <summary>The shared secret, Base32 encoded, for entering by hand.</summary>
        public required string Secret { get; init; }

        /// <summary>The <c>otpauth://totp/</c> URI. Contains the secret.</summary>
        public required string Uri { get; init; }

        /// <summary>The service, as it will appear in the authenticator.</summary>
        public required string Issuer { get; init; }

        /// <summary>The account, as it will appear in the authenticator.</summary>
        public required string Account { get; init; }

        /// <summary>The hash function, as the URI writes it.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Digits in a code.</summary>
        public required int Digits { get; init; }

        /// <summary>Seconds each code is valid for.</summary>
        public required int PeriodSeconds { get; init; }

        /// <summary>Bytes the secret decodes to.</summary>
        public required int Bytes { get; init; }

        /// <summary>What the enrollment consists of. Never contains the secret.</summary>
        public required string Composition { get; init; }

        /// <summary>How the enrollment must be delivered, confirmed and stored.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>The code a supplied secret produces at a given moment.</summary>
    /// <remarks>
    /// This verifies nothing and authenticates nobody. The supplied secret is not echoed anywhere in this
    /// response.
    /// </remarks>
    public sealed record TotpCodeResponse
    {
        /// <summary>The code, zero-padded to the requested number of digits.</summary>
        public required string Code { get; init; }

        /// <summary>Unix time in seconds the code was computed for.</summary>
        public required long UnixTimeSeconds { get; init; }

        /// <summary>The RFC 6238 counter the code came from.</summary>
        public required long Counter { get; init; }

        /// <summary>Seconds until this code is replaced by the next one.</summary>
        public required int ValidForSeconds { get; init; }

        /// <summary>The hash function used.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Digits in the code.</summary>
        public required int Digits { get; init; }

        /// <summary>Seconds each code is valid for.</summary>
        public required int PeriodSeconds { get; init; }

        /// <summary>How the code was computed. Never contains the secret.</summary>
        public required string Composition { get; init; }

        /// <summary>What this result is, and what verification still requires.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>A value re-rendered in another encoding.</summary>
    /// <remarks>
    /// Encoding is not encryption. The result is reversible by anyone and is exactly as sensitive as the
    /// input it was produced from.
    /// </remarks>
    public sealed record EncodedTextResponse
    {
        /// <summary>The encoded value.</summary>
        public required string Value { get; init; }

        /// <summary>The encoding that was applied.</summary>
        public required string Encoding { get; init; }

        /// <summary>Bytes that were encoded.</summary>
        public required int Bytes { get; init; }

        /// <summary>Characters in <see cref="Value"/>.</summary>
        public required int Length { get; init; }

        /// <summary>What was done. Never contains the input.</summary>
        public required string Composition { get; init; }

        /// <summary>Always includes that this is an encoding rather than encryption.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>The published test card numbers.</summary>
    /// <remarks>
    /// Nothing here is secret and nothing here is generated: these are the numbers the card networks
    /// publish for testing, and every real processor declines them.
    /// </remarks>
    public sealed record TestCardsResponse
    {
        /// <summary>The matching numbers.</summary>
        public required IReadOnlyList<TestCardResponse> Cards { get; init; }

        /// <summary>How many were returned.</summary>
        public required int Count { get; init; }

        /// <summary>The brands available, for a caller narrowing the list.</summary>
        public required IReadOnlyList<string> Brands { get; init; }

        /// <summary>What these numbers are and how they must be used.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>One published test card number.</summary>
    public sealed record TestCardResponse
    {
        /// <summary>The network identifier, for example <c>visa</c>.</summary>
        public required string Brand { get; init; }

        /// <summary>The network's name.</summary>
        public required string DisplayName { get; init; }

        /// <summary>The published test number.</summary>
        public required string Number { get; init; }

        /// <summary>Digits the number contains.</summary>
        public required int Digits { get; init; }

        /// <summary>Digits in the security code this network uses.</summary>
        public required int SecurityCodeDigits { get; init; }

        /// <summary>Whether the number satisfies the Luhn check. Always true for every number listed.</summary>
        public required bool LuhnValid { get; init; }

        /// <summary>What this number is useful for testing.</summary>
        public required string Description { get; init; }
    }
}
