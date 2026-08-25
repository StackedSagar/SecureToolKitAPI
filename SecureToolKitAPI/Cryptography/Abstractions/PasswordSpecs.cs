using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Character sets a generated password may draw from. Combine the individual flags, or use one of
    /// the named combinations.
    /// </summary>
    [Flags]
    public enum PasswordCharacters
    {
        /// <summary>No set selected. Not valid for generation.</summary>
        None = 0,

        /// <summary><c>a</c>–<c>z</c>.</summary>
        Lowercase = 1,

        /// <summary><c>A</c>–<c>Z</c>.</summary>
        Uppercase = 2,

        /// <summary><c>0</c>–<c>9</c>.</summary>
        Digits = 4,

        /// <summary>A curated punctuation set chosen to survive copy and paste.</summary>
        Symbols = 8,

        /// <summary>Letters in both cases, for systems that reject anything else.</summary>
        LettersOnly = Lowercase | Uppercase,

        /// <summary>Letters and digits: the "no symbols" combination.</summary>
        Alphanumeric = Lowercase | Uppercase | Digits,

        /// <summary>Every set. The default, and the strongest per character.</summary>
        All = Lowercase | Uppercase | Digits | Symbols
    }

    /// <summary>
    /// Options for a single generated password.
    /// </summary>
    /// <remarks>
    /// Defaults describe a 16-character password drawn from every character set with at least one
    /// character from each, which is a sensible general-purpose choice.
    /// </remarks>
    public sealed record PasswordSpec
    {
        /// <summary>Shortest password this API will generate.</summary>
        public const int MinimumLength = 4;

        /// <summary>Longest password this API will generate.</summary>
        public const int MaximumLength = 512;

        /// <summary>Number of characters to generate. Defaults to 16.</summary>
        public int Length { get; init; } = 16;

        /// <summary>Character sets to draw from. Defaults to <see cref="PasswordCharacters.All"/>.</summary>
        public PasswordCharacters Characters { get; init; } = PasswordCharacters.All;

        /// <summary>
        /// Removes characters that are easily confused when read aloud or retyped, such as
        /// <c>0</c> and <c>O</c>. This shrinks the alphabet, so it lowers entropy per character.
        /// </summary>
        public bool ExcludeAmbiguous { get; init; }

        /// <summary>
        /// Guarantees at least one character from every selected set, which is what most password
        /// policies check. Defaults to <c>true</c>.
        /// </summary>
        public bool RequireEachSet { get; init; } = true;

        /// <summary>
        /// Validates the combination of options.
        /// </summary>
        /// <exception cref="CryptographicRequestException">
        /// The length is out of range, no character set was selected, or the length is too short to
        /// include one character from every selected set.
        /// </exception>
        public void Validate()
        {
            if (Length is < MinimumLength or > MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"The password length must be between {MinimumLength} and {MaximumLength} characters.");
            }

            if (Characters == PasswordCharacters.None)
            {
                throw new CryptographicRequestException(
                    "At least one character set must be selected: lowercase, uppercase, digits or symbols.");
            }

            var selectedSets = SelectedSetCount();

            // Defence in depth: <see cref="MinimumLength"/> is currently at least the number of sets, so
            // the length check above already rules this out. The guard stays so that adding a character
            // set, or lowering the minimum length, fails loudly instead of silently dropping a set.
            if (RequireEachSet && Length < selectedSets)
            {
                throw new CryptographicRequestException(
                    $"A length of at least {selectedSets} characters is required to include one character "
                    + "from every selected set. Reduce the number of sets, increase the length, or do not "
                    + "require every set.");
            }
        }

        /// <summary>Number of individual character sets selected.</summary>
        public int SelectedSetCount()
        {
            var count = 0;

            if (Characters.HasFlag(PasswordCharacters.Lowercase)) count++;
            if (Characters.HasFlag(PasswordCharacters.Uppercase)) count++;
            if (Characters.HasFlag(PasswordCharacters.Digits)) count++;
            if (Characters.HasFlag(PasswordCharacters.Symbols)) count++;

            return count;
        }

        /// <summary>
        /// Describes the alphabet these options draw from, for example
        /// <c>lowercase, uppercase, digits, symbols (84 character alphabet)</c>.
        /// </summary>
        /// <returns>A caller-safe description; no password is generated and none is revealed.</returns>
        /// <exception cref="CryptographicRequestException">No character set is selected.</exception>
        /// <remarks>
        /// Lets an endpoint document what a preset would produce without having to generate a password
        /// just to describe it.
        /// </remarks>
        public string Describe() => PasswordCharsets.Describe(Characters, ExcludeAmbiguous);
    }

    /// <summary>
    /// Options for generating several passwords in one request, for example when provisioning a batch
    /// of accounts.
    /// </summary>
    public sealed record BulkPasswordSpec
    {
        /// <summary>Fewest passwords a bulk request may ask for.</summary>
        public const int MinimumCount = 1;

        /// <summary>Most passwords a bulk request may ask for, which bounds the response size.</summary>
        public const int MaximumCount = 100;

        /// <summary>Options applied to every password in the batch.</summary>
        public PasswordSpec Password { get; init; } = new();

        /// <summary>Number of passwords to generate. Defaults to 10.</summary>
        public int Count { get; init; } = 10;

        /// <summary>
        /// Validates the batch size and the password options.
        /// </summary>
        /// <exception cref="CryptographicRequestException">The count is out of range, or the password options are not valid.</exception>
        public void Validate()
        {
            if (Count is < MinimumCount or > MaximumCount)
            {
                throw new CryptographicRequestException(
                    $"The number of passwords must be between {MinimumCount} and {MaximumCount}.");
            }

            Password.Validate();
        }
    }

    /// <summary>
    /// Options for a passphrase: several words chosen independently from a fixed word list and joined
    /// by a separator. Easier to type and remember than a random string of the same strength.
    /// </summary>
    public sealed record PassphraseSpec
    {
        /// <summary>Fewest words a passphrase may contain.</summary>
        public const int MinimumWords = 3;

        /// <summary>Most words a passphrase may contain.</summary>
        public const int MaximumWords = 24;

        /// <summary>Longest separator accepted between words.</summary>
        public const int MaximumSeparatorLength = 4;

        /// <summary>Number of words to choose. Defaults to 6.</summary>
        public int Words { get; init; } = 6;

        /// <summary>Text placed between words. Defaults to a hyphen; may be empty.</summary>
        public string Separator { get; init; } = "-";

        /// <summary>Capitalises the first letter of every word.</summary>
        public bool Capitalize { get; init; }

        /// <summary>Appends a random digit, for policies that insist on one.</summary>
        public bool IncludeNumber { get; init; }

        /// <summary>Appends a random symbol, for policies that insist on one.</summary>
        public bool IncludeSymbol { get; init; }

        /// <summary>
        /// Validates the word count and the separator.
        /// </summary>
        /// <exception cref="CryptographicRequestException">
        /// The word count is out of range, or the separator is too long or contains whitespace or
        /// control characters.
        /// </exception>
        public void Validate()
        {
            if (Words is < MinimumWords or > MaximumWords)
            {
                throw new CryptographicRequestException(
                    $"The number of words must be between {MinimumWords} and {MaximumWords}.");
            }

            if (Separator.Length > MaximumSeparatorLength)
            {
                throw new CryptographicRequestException(
                    $"The separator must be at most {MaximumSeparatorLength} characters.");
            }

            if (Separator.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            {
                throw new CryptographicRequestException(
                    "The separator must not contain whitespace or control characters.");
            }
        }
    }

    /// <summary>
    /// Options for a pronounceable value built from alternating consonant and vowel sounds. Easier to
    /// read out than a random string, and correspondingly weaker per character.
    /// </summary>
    public sealed record PronounceableSpec
    {
        /// <summary>Fewest syllables accepted.</summary>
        public const int MinimumSyllables = 2;

        /// <summary>Most syllables accepted.</summary>
        public const int MaximumSyllables = 12;

        /// <summary>Number of syllables to generate. Defaults to 6.</summary>
        public int Syllables { get; init; } = 6;

        /// <summary>Capitalises the first letter of the result.</summary>
        public bool Capitalize { get; init; }

        /// <summary>Appends a random digit, for policies that insist on one.</summary>
        public bool IncludeNumber { get; init; }

        /// <summary>
        /// Validates the syllable count.
        /// </summary>
        /// <exception cref="CryptographicRequestException">The syllable count is out of range.</exception>
        public void Validate()
        {
            if (Syllables is < MinimumSyllables or > MaximumSyllables)
            {
                throw new CryptographicRequestException(
                    $"The number of syllables must be between {MinimumSyllables} and {MaximumSyllables}.");
            }
        }
    }

    /// <summary>
    /// Options for a numeric PIN. A PIN drawn from ten digits is weak by construction; it is offered
    /// only for systems that accept nothing else, such as door locks and SIM cards.
    /// </summary>
    public sealed record PinSpec
    {
        /// <summary>Shortest PIN accepted.</summary>
        public const int MinimumLength = 3;

        /// <summary>Longest PIN accepted.</summary>
        public const int MaximumLength = 16;

        /// <summary>Number of digits to generate. Defaults to 6.</summary>
        public int Length { get; init; } = 6;

        /// <summary>
        /// Validates the PIN length.
        /// </summary>
        /// <exception cref="CryptographicRequestException">The length is out of range.</exception>
        public void Validate()
        {
            if (Length is < MinimumLength or > MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"The PIN length must be between {MinimumLength} and {MaximumLength} digits.");
            }
        }
    }

    /// <summary>
    /// Options for a suggested username. A username is a public identifier, not a secret, so it is
    /// generated for readability rather than for strength.
    /// </summary>
    public sealed record UsernameSpec
    {
        /// <summary>Fewest words a username may contain.</summary>
        public const int MinimumWords = 1;

        /// <summary>Most words a username may contain.</summary>
        public const int MaximumWords = 4;

        /// <summary>Longest separator accepted between words.</summary>
        public const int MaximumSeparatorLength = 2;

        /// <summary>Number of words to combine. Defaults to 2.</summary>
        public int Words { get; init; } = 2;

        /// <summary>Text placed between words. Defaults to empty.</summary>
        public string Separator { get; init; } = string.Empty;

        /// <summary>Capitalises the first letter of every word.</summary>
        public bool Capitalize { get; init; }

        /// <summary>Appends a short random number, which helps avoid collisions.</summary>
        public bool IncludeNumber { get; init; } = true;

        /// <summary>
        /// Validates the word count and the separator.
        /// </summary>
        /// <exception cref="CryptographicRequestException">
        /// The word count is out of range, or the separator is too long or is not a letter, digit,
        /// hyphen, underscore or dot.
        /// </exception>
        public void Validate()
        {
            if (Words is < MinimumWords or > MaximumWords)
            {
                throw new CryptographicRequestException(
                    $"The number of words must be between {MinimumWords} and {MaximumWords}.");
            }

            if (Separator.Length > MaximumSeparatorLength)
            {
                throw new CryptographicRequestException(
                    $"The separator must be at most {MaximumSeparatorLength} characters.");
            }

            if (!Separator.All(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.'))
            {
                throw new CryptographicRequestException(
                    "The separator may only contain letters, digits, hyphens, underscores or dots.");
            }
        }
    }
}
