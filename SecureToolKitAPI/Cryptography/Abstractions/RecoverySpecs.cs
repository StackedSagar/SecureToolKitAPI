using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>Which symbols a backup code is drawn from.</summary>
    /// <remarks>
    /// Both formats are chosen for values a person reads off a screen once and types back in under
    /// pressure, so neither contains characters that are hard to tell apart.
    /// </remarks>
    public enum BackupCodeFormat
    {
        /// <summary>
        /// Digits and uppercase letters, excluding I, L, O and U — Crockford's Base32 alphabet, 32
        /// symbols, five bits per character.
        /// </summary>
        Alphanumeric,

        /// <summary>
        /// Digits only, 10 symbols, about 3.3 bits per character. Easier to enter on a numeric keypad,
        /// so a code of the same length is considerably weaker.
        /// </summary>
        Numeric
    }

    /// <summary>
    /// Options for a set of single-use backup codes: the codes a person keeps for the day their second
    /// factor is unavailable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Codes are sized in characters rather than bits because they are transcribed by hand, and each is
    /// drawn independently: one code being used or leaked tells an attacker nothing about the others.
    /// </para>
    /// <para>
    /// The defaults describe ten 10-character codes over 32 symbols, about 50 bits each. That is far
    /// below what a password needs, and deliberately so — a backup code is only useful against an online
    /// login that rate-limits and invalidates the code once it is used. Anything relying on these codes
    /// must enforce both.
    /// </para>
    /// </remarks>
    public sealed record BackupCodeSpec
    {
        /// <summary>Fewest codes a request may ask for.</summary>
        public const int MinimumCount = 1;

        /// <summary>Most codes a request may ask for, which bounds the response size.</summary>
        public const int MaximumCount = 50;

        /// <summary>Shortest code this API will generate.</summary>
        public const int MinimumLength = 6;

        /// <summary>Longest code this API will generate.</summary>
        public const int MaximumLength = 32;

        /// <summary>Largest grouping interval accepted.</summary>
        public const int MaximumGroupSize = 16;

        /// <summary>Number of codes to generate. Defaults to 10.</summary>
        public int Count { get; init; } = 10;

        /// <summary>
        /// Characters in each code, before any grouping separators are added. Defaults to 10.
        /// </summary>
        public int Length { get; init; } = 10;

        /// <summary>
        /// Symbols to draw from. Defaults to <see cref="BackupCodeFormat.Alphanumeric"/>.
        /// </summary>
        public BackupCodeFormat Format { get; init; } = BackupCodeFormat.Alphanumeric;

        /// <summary>
        /// Inserts a hyphen every this many characters, so a code can be read back in chunks. Defaults
        /// to 5; zero returns the code unbroken. Grouping changes only how the code is written down, so
        /// it adds no entropy.
        /// </summary>
        public int GroupSize { get; init; } = 5;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            if (Count is < MinimumCount or > MaximumCount)
            {
                throw new CryptographicRequestException(
                    $"The number of backup codes must be between {MinimumCount} and {MaximumCount}.");
            }

            if (Length is < MinimumLength or > MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"A backup code must be between {MinimumLength} and {MaximumLength} characters.");
            }

            if (!Enum.IsDefined(Format))
            {
                throw new CryptographicRequestException("The requested backup code format is not supported.");
            }

            if (GroupSize is < 0 or > MaximumGroupSize)
            {
                throw new CryptographicRequestException(
                    $"The group size must be between 0 and {MaximumGroupSize} characters, "
                    + "where 0 leaves the code unbroken.");
            }
        }

        /// <summary>Describes the symbols these options draw from, for the response.</summary>
        /// <returns>A caller-safe description; no code is generated and none is revealed.</returns>
        public string Describe() => SecretText.Describe(Format);
    }

    /// <summary>
    /// Options for a recovery key: one long value, written in groups, that restores access to an account
    /// or decrypts a vault when every other factor is gone.
    /// </summary>
    /// <remarks>
    /// A recovery key protects everything behind it on its own, with no second factor and often no rate
    /// limit, so it is sized to stand up offline. The defaults describe five groups of five characters
    /// over 32 symbols, about 125 bits.
    /// </remarks>
    public sealed record RecoveryKeySpec
    {
        /// <summary>Fewest groups a recovery key may have.</summary>
        public const int MinimumGroups = 2;

        /// <summary>Most groups a recovery key may have.</summary>
        public const int MaximumGroups = 16;

        /// <summary>Fewest characters a group may contain.</summary>
        public const int MinimumGroupSize = 4;

        /// <summary>Most characters a group may contain.</summary>
        public const int MaximumGroupSize = 8;

        /// <summary>Number of hyphen-separated groups. Defaults to 5.</summary>
        public int Groups { get; init; } = 5;

        /// <summary>Characters in each group. Defaults to 5.</summary>
        public int GroupSize { get; init; } = 5;

        /// <summary>
        /// Symbols to draw from. Defaults to <see cref="BackupCodeFormat.Alphanumeric"/>; a numeric
        /// recovery key of the same length is much weaker.
        /// </summary>
        public BackupCodeFormat Format { get; init; } = BackupCodeFormat.Alphanumeric;

        /// <summary>Total characters of randomness, excluding the separators.</summary>
        public int Characters => Groups * GroupSize;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            if (Groups is < MinimumGroups or > MaximumGroups)
            {
                throw new CryptographicRequestException(
                    $"The number of groups must be between {MinimumGroups} and {MaximumGroups}.");
            }

            if (GroupSize is < MinimumGroupSize or > MaximumGroupSize)
            {
                throw new CryptographicRequestException(
                    $"The group size must be between {MinimumGroupSize} and {MaximumGroupSize} characters.");
            }

            if (!Enum.IsDefined(Format))
            {
                throw new CryptographicRequestException("The requested recovery key format is not supported.");
            }
        }

        /// <summary>Describes the symbols these options draw from, for the response.</summary>
        /// <returns>A caller-safe description; no key is generated and none is revealed.</returns>
        public string Describe() => SecretText.Describe(Format);
    }

    /// <summary>
    /// Options for the entropy calculator: how much randomness a value of a given length, drawn from a
    /// given alphabet, would carry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This describes a value that has not been generated yet, which is what makes the answer exact: the
    /// entropy of a random choice is a property of how it is made, not of the characters that came out.
    /// Nothing here accepts or inspects an actual password — that is what the strength check is for, and
    /// it can only ever estimate.
    /// </para>
    /// <para>
    /// The alphabet is given either as the character sets this API generates from, or as a bare size for
    /// a scheme it knows nothing about. Supplying both would be ambiguous and is refused.
    /// </para>
    /// </remarks>
    public sealed record EntropySpec
    {
        /// <summary>Fewest characters that can be described.</summary>
        public const int MinimumCount = 1;

        /// <summary>Most characters that can be described.</summary>
        public const int MaximumCount = 4096;

        /// <summary>Smallest alphabet that carries any entropy at all.</summary>
        public const int MinimumAlphabetSize = 2;

        /// <summary>
        /// Largest alphabet accepted. Comfortably above any keyboard alphabet, and above the size of a
        /// large word list, so a passphrase can be described with words as the characters.
        /// </summary>
        public const int MaximumAlphabetSize = 1_048_576;

        /// <summary>
        /// How many characters — or words, for a passphrase — are chosen independently. Defaults to 16.
        /// </summary>
        public int Count { get; init; } = 16;

        /// <summary>
        /// Character sets the value is drawn from. Defaults to <see cref="PasswordCharacters.All"/> when
        /// no <see cref="AlphabetSize"/> is given.
        /// </summary>
        public PasswordCharacters? Characters { get; init; }

        /// <summary>
        /// Drops the easily confused characters from the selected sets, matching the option the password
        /// endpoints take. Ignored when <see cref="AlphabetSize"/> is given.
        /// </summary>
        public bool ExcludeAmbiguous { get; init; }

        /// <summary>
        /// Number of symbols in the alphabet, for a scheme this API does not generate — a word list, a
        /// custom code alphabet. Mutually exclusive with <see cref="Characters"/>.
        /// </summary>
        public int? AlphabetSize { get; init; }

        /// <summary>Validates the options.</summary>
        /// <exception cref="CryptographicRequestException">
        /// The count or alphabet size is out of range, both ways of naming the alphabet were used at
        /// once, or no character set was selected.
        /// </exception>
        public void Validate()
        {
            if (Count is < MinimumCount or > MaximumCount)
            {
                throw new CryptographicRequestException(
                    $"The number of characters must be between {MinimumCount} and {MaximumCount}.");
            }

            if (Characters is not null && AlphabetSize is not null)
            {
                throw new CryptographicRequestException(
                    "Supply either character sets or an alphabet size, not both.");
            }

            if (AlphabetSize is { } size)
            {
                if (size is < MinimumAlphabetSize or > MaximumAlphabetSize)
                {
                    throw new CryptographicRequestException(
                        $"The alphabet size must be between {MinimumAlphabetSize} and {MaximumAlphabetSize}.");
                }

                return;
            }

            if (Characters == PasswordCharacters.None)
            {
                throw new CryptographicRequestException(
                    "At least one character set must be selected: lowercase, uppercase, digits or symbols.");
            }
        }

        /// <summary>Number of symbols the value is drawn from, however the alphabet was named.</summary>
        /// <exception cref="CryptographicRequestException">No character set is selected.</exception>
        public int ResolvedAlphabetSize() =>
            AlphabetSize ?? PasswordCharsets.For(Characters ?? PasswordCharacters.All, ExcludeAmbiguous).Length;

        /// <summary>Describes the alphabet, for the response.</summary>
        /// <returns>A caller-safe description; nothing is generated and no value is revealed.</returns>
        /// <exception cref="CryptographicRequestException">No character set is selected.</exception>
        public string Describe() =>
            AlphabetSize is { } size
                ? $"{size} character alphabet"
                : PasswordCharsets.Describe(Characters ?? PasswordCharacters.All, ExcludeAmbiguous);
    }

    /// <summary>
    /// Reads the caller-facing spelling of the recovery options and turns it into the corresponding
    /// option, so an unknown value is reported as a bad request rather than silently falling back to a
    /// default.
    /// </summary>
    /// <remarks>
    /// Matching ignores case, hyphens, underscores and spaces. An omitted value means "use the default".
    /// </remarks>
    public static class RecoveryOptions
    {
        /// <summary>Resolves a backup code format name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved format.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported format.</exception>
        public static BackupCodeFormat ParseBackupCodeFormat(string? value) =>
            OptionName.Parse(value, BackupCodeFormat.Alphanumeric, "backup code format");
    }
}
