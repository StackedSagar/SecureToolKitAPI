using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// The alphabets a generated password is drawn from, and the helpers that describe them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The symbol set is deliberately curated rather than "all printable punctuation". Quotes,
    /// backslashes, backticks, semicolons, colons, commas, dots, slashes and pipes are excluded because
    /// they are the characters most often mangled when a password is pasted into a shell, a CSV file, a
    /// JSON document, a connection string or a URL. Dropping them costs a fraction of a bit per
    /// character and removes a common class of support problem.
    /// </para>
    /// <para>
    /// Nothing here chooses characters; selection is the generator's job and must go through
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>.
    /// </para>
    /// </remarks>
    internal static class PasswordCharsets
    {
        /// <summary>The lowercase letters.</summary>
        internal const string Lowercase = "abcdefghijklmnopqrstuvwxyz";

        /// <summary>The uppercase letters.</summary>
        internal const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        /// <summary>The decimal digits.</summary>
        internal const string Digits = "0123456789";

        /// <summary>Punctuation that survives copy and paste through shells, CSV, JSON and URLs.</summary>
        internal const string Symbols = "!#$%&()*+-<=>?@[]^_{}~";

        /// <summary>
        /// Characters that are easily confused with one another when a value is read aloud or retyped:
        /// zero and capital O, one against lowercase L and capital I, and the digit/letter lookalikes
        /// five/S, two/Z and eight/B.
        /// </summary>
        internal const string Ambiguous = "0O1lI5S2Z8B";

        /// <summary>The individual sets, in the order they are reported and concatenated.</summary>
        private static readonly PasswordCharacters[] IndividualSets =
        [
            PasswordCharacters.Lowercase,
            PasswordCharacters.Uppercase,
            PasswordCharacters.Digits,
            PasswordCharacters.Symbols
        ];

        /// <summary>
        /// Builds the full alphabet for a selection of character sets.
        /// </summary>
        /// <param name="characters">The selected sets.</param>
        /// <param name="excludeAmbiguous">Whether to drop the easily confused characters.</param>
        /// <returns>The alphabet, with the sets concatenated in a stable order.</returns>
        /// <exception cref="CryptographicRequestException">
        /// No set was selected, or every character of every selected set was excluded.
        /// </exception>
        internal static string For(PasswordCharacters characters, bool excludeAmbiguous)
        {
            if (characters == PasswordCharacters.None)
            {
                throw new CryptographicRequestException(
                    "At least one character set must be selected: lowercase, uppercase, digits or symbols.");
            }

            var alphabet = string.Concat(
                SelectedSets(characters).Select(set => Set(set, excludeAmbiguous)));

            return alphabet.Length > 1
                ? alphabet
                : throw new CryptographicRequestException(
                    "The selected character sets leave too few characters to generate from. Select more "
                    + "sets, or do not exclude ambiguous characters.");
        }

        /// <summary>
        /// Returns the characters of one individual set.
        /// </summary>
        /// <param name="set">A single set — not a combination.</param>
        /// <param name="excludeAmbiguous">Whether to drop the easily confused characters.</param>
        /// <exception cref="CryptographicRequestException">Every character of the set was excluded.</exception>
        internal static string Set(PasswordCharacters set, bool excludeAmbiguous)
        {
            var characters = set switch
            {
                PasswordCharacters.Lowercase => Lowercase,
                PasswordCharacters.Uppercase => Uppercase,
                PasswordCharacters.Digits => Digits,
                PasswordCharacters.Symbols => Symbols,
                _ => throw new ArgumentOutOfRangeException(
                    nameof(set), "Only a single character set can be resolved at a time.")
            };

            if (!excludeAmbiguous)
            {
                return characters;
            }

            var remaining = new string(
                characters.Where(character => !Ambiguous.Contains(character, StringComparison.Ordinal)).ToArray());

            return remaining.Length > 0
                ? remaining
                : throw new CryptographicRequestException(
                    $"Excluding ambiguous characters leaves the {NameOf(set)} set empty.");
        }

        /// <summary>
        /// Lists the individual sets contained in a selection, in a stable order.
        /// </summary>
        /// <param name="characters">The selected sets, possibly a combination.</param>
        internal static IReadOnlyList<PasswordCharacters> SelectedSets(PasswordCharacters characters) =>
            [.. IndividualSets.Where(set => characters.HasFlag(set))];

        /// <summary>
        /// Describes what a value was built from, for example
        /// <c>lowercase, uppercase, digits, symbols (73 character alphabet, ambiguous characters excluded)</c>.
        /// </summary>
        /// <param name="characters">The selected sets.</param>
        /// <param name="excludeAmbiguous">Whether the easily confused characters were dropped.</param>
        /// <returns>A caller-safe description that never contains the generated value.</returns>
        internal static string Describe(PasswordCharacters characters, bool excludeAmbiguous)
        {
            var names = string.Join(", ", SelectedSets(characters).Select(NameOf));
            var size = For(characters, excludeAmbiguous).Length;
            var exclusion = excludeAmbiguous ? ", ambiguous characters excluded" : string.Empty;

            return $"{names} ({size} character alphabet{exclusion})";
        }

        /// <summary>Caller-facing name of one individual set.</summary>
        /// <param name="set">A single set — not a combination.</param>
        private static string NameOf(PasswordCharacters set) => set switch
        {
            PasswordCharacters.Lowercase => "lowercase",
            PasswordCharacters.Uppercase => "uppercase",
            PasswordCharacters.Digits => "digits",
            PasswordCharacters.Symbols => "symbols",
            _ => set.ToString()
        };
    }
}
