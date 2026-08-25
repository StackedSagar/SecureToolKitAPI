using System.Text.Json.Serialization;

namespace SecureToolKitAPI.Contracts.Passwords
{
    /// <summary>
    /// Options for a generated password. Every member is optional; omit the body entirely to accept the
    /// defaults, which are a 16-character password drawn from every character set.
    /// </summary>
    /// <remarks>
    /// Each character set is included unless it is explicitly excluded, so
    /// <c>{ "includeSymbols": false }</c> is enough to ask for a password without punctuation. Values
    /// outside the documented ranges are reported as a 400 problem response rather than being clamped
    /// silently.
    /// </remarks>
    public sealed record PasswordRequest
    {
        /// <summary>Number of characters. Between 4 and 512; defaults to 16.</summary>
        public int? Length { get; init; }

        /// <summary>Include <c>a</c>–<c>z</c>. Defaults to <c>true</c>.</summary>
        public bool? IncludeLowercase { get; init; }

        /// <summary>Include <c>A</c>–<c>Z</c>. Defaults to <c>true</c>.</summary>
        public bool? IncludeUppercase { get; init; }

        /// <summary>Include <c>0</c>–<c>9</c>. Defaults to <c>true</c>.</summary>
        public bool? IncludeDigits { get; init; }

        /// <summary>Include punctuation. Defaults to <c>true</c>.</summary>
        public bool? IncludeSymbols { get; init; }

        /// <summary>
        /// Drop characters that are easily confused when read aloud or retyped, such as <c>0</c> and
        /// <c>O</c>. Defaults to <c>false</c>.
        /// </summary>
        public bool? ExcludeAmbiguous { get; init; }

        /// <summary>
        /// Guarantee at least one character from every selected set, which is what most password
        /// policies check. Defaults to <c>true</c>.
        /// </summary>
        public bool? RequireEachSet { get; init; }
    }

    /// <summary>Request for several independently generated passwords that share one set of options.</summary>
    public sealed record BulkPasswordRequest
    {
        /// <summary>How many passwords to generate. Between 1 and 100; defaults to 10.</summary>
        public int? Count { get; init; }

        /// <summary>Options applied to every password. Omit to use the defaults.</summary>
        public PasswordRequest? Password { get; init; }
    }

    /// <summary>Options for a generated passphrase.</summary>
    public sealed record PassphraseRequest
    {
        /// <summary>How many words to choose. Between 3 and 24; defaults to 6.</summary>
        public int? Words { get; init; }

        /// <summary>
        /// Text placed between words. At most 4 characters, no whitespace; defaults to a hyphen. Pass an
        /// empty string to run the words together.
        /// </summary>
        public string? Separator { get; init; }

        /// <summary>Capitalise the first letter of every word. Defaults to <c>false</c>.</summary>
        public bool? Capitalize { get; init; }

        /// <summary>Append a random digit, for policies that insist on one. Defaults to <c>false</c>.</summary>
        public bool? IncludeNumber { get; init; }

        /// <summary>Append a random symbol, for policies that insist on one. Defaults to <c>false</c>.</summary>
        public bool? IncludeSymbol { get; init; }
    }

    /// <summary>Options for a memorable passphrase: a shorter, decorated passphrase.</summary>
    public sealed record MemorableRequest
    {
        /// <summary>How many words to choose. Between 3 and 24; defaults to 4.</summary>
        public int? Words { get; init; }
    }

    /// <summary>Options for a pronounceable value.</summary>
    public sealed record PronounceableRequest
    {
        /// <summary>How many syllables to generate. Between 2 and 12; defaults to 6.</summary>
        public int? Syllables { get; init; }

        /// <summary>Capitalise the first letter. Defaults to <c>false</c>.</summary>
        public bool? Capitalize { get; init; }

        /// <summary>Append a random digit. Defaults to <c>false</c>.</summary>
        public bool? IncludeNumber { get; init; }
    }

    /// <summary>Options for a numeric PIN.</summary>
    public sealed record PinRequest
    {
        /// <summary>How many digits to generate. Between 3 and 16; defaults to 6.</summary>
        public int? Length { get; init; }
    }

    /// <summary>Options for a suggested username.</summary>
    public sealed record UsernameRequest
    {
        /// <summary>How many words to combine. Between 1 and 4; defaults to 2.</summary>
        public int? Words { get; init; }

        /// <summary>
        /// Text placed between words. At most 2 characters, and only letters, digits, hyphens,
        /// underscores or dots. Defaults to empty.
        /// </summary>
        public string? Separator { get; init; }

        /// <summary>Capitalise the first letter of every word. Defaults to <c>false</c>.</summary>
        public bool? Capitalize { get; init; }

        /// <summary>Append a two-digit number, which helps avoid collisions. Defaults to <c>true</c>.</summary>
        public bool? IncludeNumber { get; init; }
    }

    /// <summary>
    /// A generated password, passphrase, PIN or username, with the figures that describe how hard it is
    /// to guess.
    /// </summary>
    /// <remarks>
    /// <see cref="Value"/> is secret material for every endpoint except the username suggestion. Treat
    /// this response as sensitive: do not log it, do not cache it and do not put it in a URL.
    /// </remarks>
    public sealed record PasswordResponse
    {
        /// <summary>The generated value.</summary>
        public required string Value { get; init; }

        /// <summary>Number of characters in the value.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of the generation process in bits: how much guessing an attacker who knows exactly
        /// how the value was made would still have to do. Higher is better; this is a conservative
        /// figure.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>, for example <c>Strong</c>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the value was built from. Never contains the value itself.</summary>
        public required string Composition { get; init; }

        /// <summary>Name of the preset used, when the value came from one.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Preset { get; init; }

        /// <summary>Non-fatal advisories, for example that the value is weaker than recommended.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>Several independently generated passwords.</summary>
    /// <remarks>This response contains secret material. Treat it as sensitive and do not log it.</remarks>
    public sealed record BulkPasswordResponse
    {
        /// <summary>How many passwords were generated.</summary>
        public required int Count { get; init; }

        /// <summary>The generated passwords, each independent of the others.</summary>
        public required IReadOnlyList<PasswordResponse> Passwords { get; init; }
    }

    /// <summary>A named set of password options offered by this API.</summary>
    public sealed record PasswordPresetResponse
    {
        /// <summary>Identifier to use in <c>POST /api/password/presets/{preset}</c>.</summary>
        public required string Name { get; init; }

        /// <summary>What the preset is for, and why its options were chosen.</summary>
        public required string Description { get; init; }

        /// <summary>Length of the password the preset produces.</summary>
        public required int Length { get; init; }

        /// <summary>Character sets the preset draws from.</summary>
        public required string Composition { get; init; }

        /// <summary>Advisories that apply to every password generated from this preset.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
