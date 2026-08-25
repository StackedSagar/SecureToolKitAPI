namespace SecureToolKitAPI.Contracts.Recovery
{
    /// <summary>
    /// Options for a set of single-use backup codes. Every member is optional; omit the body entirely to
    /// accept the defaults, which are ten 10-character alphanumeric codes written in groups of five.
    /// </summary>
    /// <remarks>
    /// Values outside the documented ranges are reported as a 400 problem response rather than being
    /// clamped silently.
    /// </remarks>
    public sealed record BackupCodeRequest
    {
        /// <summary>How many codes to generate. Between 1 and 50; defaults to 10.</summary>
        public int? Count { get; init; }

        /// <summary>
        /// Characters of randomness in each code, excluding the group separators. Between 6 and 32;
        /// defaults to 10.
        /// </summary>
        public int? Length { get; init; }

        /// <summary>
        /// Which symbols to draw from: <c>Alphanumeric</c> for digits and unambiguous uppercase letters,
        /// or <c>Numeric</c> for digits only. Defaults to <c>Alphanumeric</c>.
        /// </summary>
        public string? Format { get; init; }

        /// <summary>
        /// Insert a hyphen every this many characters, so a code can be read back in chunks. Between 0 and
        /// 16; defaults to 5. Zero returns the code unbroken. Grouping adds no entropy.
        /// </summary>
        public int? GroupSize { get; init; }
    }

    /// <summary>
    /// Options for a recovery key. Every member is optional; omit the body entirely to accept the
    /// defaults, which are five groups of five alphanumeric characters, about 125 bits.
    /// </summary>
    public sealed record RecoveryKeyRequest
    {
        /// <summary>How many hyphen-separated groups. Between 2 and 16; defaults to 5.</summary>
        public int? Groups { get; init; }

        /// <summary>Characters in each group. Between 4 and 8; defaults to 5.</summary>
        public int? GroupSize { get; init; }

        /// <summary>
        /// Which symbols to draw from: <c>Alphanumeric</c> or <c>Numeric</c>. Defaults to
        /// <c>Alphanumeric</c>; a numeric key of the same length is much weaker.
        /// </summary>
        public string? Format { get; init; }
    }

    /// <summary>The password to assess.</summary>
    /// <remarks>
    /// <para>
    /// The password travels in the request body and only in the request body, because a query string ends
    /// up in server logs, proxy logs and browser history. This API does not log it, store it or return it.
    /// </para>
    /// <para>
    /// Sending a live password to any service — including this one — is a decision worth making
    /// deliberately. Nothing is retained here, but the request still crosses the network.
    /// </para>
    /// </remarks>
    public sealed record PasswordStrengthRequest
    {
        /// <summary>The password to assess. Required, and at most 512 characters.</summary>
        public string? Password { get; init; }
    }

    /// <summary>
    /// Describes a password that has not been generated yet, so its entropy can be calculated exactly.
    /// </summary>
    /// <remarks>
    /// Name the alphabet either with the character-set flags, matching the password endpoints, or with a
    /// bare <see cref="AlphabetSize"/> for a scheme this API does not generate — a word list, a custom
    /// code alphabet. Supplying both is ambiguous and is refused.
    /// </remarks>
    public sealed record EntropyRequest
    {
        /// <summary>
        /// How many characters — or words, for a passphrase — are chosen independently. Between 1 and
        /// 4096; defaults to 16.
        /// </summary>
        public int? Count { get; init; }

        /// <summary>Include <c>a</c>–<c>z</c>. Defaults to <c>true</c> when no alphabet size is given.</summary>
        public bool? IncludeLowercase { get; init; }

        /// <summary>Include <c>A</c>–<c>Z</c>. Defaults to <c>true</c> when no alphabet size is given.</summary>
        public bool? IncludeUppercase { get; init; }

        /// <summary>Include <c>0</c>–<c>9</c>. Defaults to <c>true</c> when no alphabet size is given.</summary>
        public bool? IncludeDigits { get; init; }

        /// <summary>Include punctuation. Defaults to <c>true</c> when no alphabet size is given.</summary>
        public bool? IncludeSymbols { get; init; }

        /// <summary>
        /// Drop characters that are easily confused, such as <c>0</c> and <c>O</c>. Defaults to
        /// <c>false</c>. Ignored when <see cref="AlphabetSize"/> is given.
        /// </summary>
        public bool? ExcludeAmbiguous { get; init; }

        /// <summary>
        /// Number of symbols in the alphabet, for a scheme described by size rather than by character
        /// set. Between 2 and 1048576. Cannot be combined with the character-set flags.
        /// </summary>
        public int? AlphabetSize { get; init; }
    }

    /// <summary>A generated set of single-use backup codes.</summary>
    /// <remarks>
    /// Every code here is live credential material, returned once and not stored by this API. Do not log
    /// this response, do not cache it and do not put a code in a URL.
    /// </remarks>
    public sealed record BackupCodesResponse
    {
        /// <summary>The codes, each drawn independently of the others.</summary>
        public required IReadOnlyList<string> Codes { get; init; }

        /// <summary>How many codes were generated.</summary>
        public required int Count { get; init; }

        /// <summary>Characters of randomness in each code, excluding the separators.</summary>
        public required int Length { get; init; }

        /// <summary>Entropy of one code, in bits.</summary>
        public required double EntropyBitsPerCode { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBitsPerCode"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the codes were built from. Never contains a code.</summary>
        public required string Composition { get; init; }

        /// <summary>What a caller must do for codes of this strength to be safe.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>A generated recovery key.</summary>
    /// <remarks>
    /// This is live credential material that restores access on its own, returned once and not stored by
    /// this API. Do not log this response and do not put the key in a URL.
    /// </remarks>
    public sealed record RecoveryKeyResponse
    {
        /// <summary>The recovery key, including its group separators.</summary>
        public required string Value { get; init; }

        /// <summary>Characters of randomness, excluding the separators.</summary>
        public required int Characters { get; init; }

        /// <summary>Number of groups the key is written in.</summary>
        public required int Groups { get; init; }

        /// <summary>Entropy of the key, in bits.</summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the key was built from, and how it is grouped. Never contains the key.</summary>
        public required string Composition { get; init; }

        /// <summary>How the key must be stored and verified.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>What can be said about the strength of a password that was supplied.</summary>
    /// <remarks>
    /// The password is not echoed here, and no field quotes any part of it. Every figure is an upper
    /// bound: see <see cref="Warnings"/> for what that means in practice.
    /// </remarks>
    public sealed record PasswordStrengthResponse
    {
        /// <summary>Number of characters examined.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Estimated entropy in bits, and an upper bound: a guesser who works out how the password was
        /// chosen needs less.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the password appears to be built from, without quoting any of it.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Base ten logarithm of the number of guesses <see cref="EntropyBits"/> implies — a logarithm
        /// because the count itself exceeds every numeric type at any real strength.
        /// </summary>
        public required double GuessesLog10 { get; init; }

        /// <summary>Patterns that lowered the estimate. Each names a pattern, never a character.</summary>
        public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();

        /// <summary>What to do about the findings, and what this check cannot tell you.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>The entropy a described password would carry.</summary>
    public sealed record EntropyResponse
    {
        /// <summary>Number of characters described.</summary>
        public required int Count { get; init; }

        /// <summary>Number of symbols each character is drawn from.</summary>
        public required int AlphabetSize { get; init; }

        /// <summary>Entropy per character, in bits.</summary>
        public required double EntropyBitsPerCharacter { get; init; }

        /// <summary>Total entropy, in bits.</summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the alphabet consists of.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Base ten logarithm of the number of possible values — a logarithm because the count itself
        /// exceeds every numeric type well before the interesting sizes.
        /// </summary>
        public required double GuessesLog10 { get; init; }

        /// <summary>What this figure assumes, and when it does not hold.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
