using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.PasswordGeneration
{
    /// <summary>
    /// Generates passwords, passphrases, pronounceable values, PINs and usernames.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every choice comes from <see cref="RandomNumberGenerator"/> — <c>GetItems</c> to sample from an
    /// alphabet or word list, <c>GetInt32</c> for a single element and <c>Shuffle</c> to place the
    /// guaranteed characters — so no sampling is hand-rolled and the reported entropy is real.
    /// </para>
    /// <para>
    /// The class is stateless and therefore safe to share as a singleton. Working buffers are cleared
    /// once the value has been built; the returned string itself is immutable and can only be discarded
    /// by the caller.
    /// </para>
    /// </remarks>
    public sealed class PasswordGenerator : IPasswordGenerator
    {
        /// <summary>
        /// Consonant sounds a pronounceable value is built from, including the clusters English readers
        /// expect at the start of a syllable.
        /// </summary>
        private static readonly string[] Consonants =
        [
            "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "z",
            "bl", "br", "ch", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "pl", "pr", "sh", "sk", "sl",
            "sm", "sn", "sp", "st", "th", "tr", "tw"
        ];

        /// <summary>Vowel sounds a pronounceable value is built from.</summary>
        private static readonly string[] Vowels =
        [
            "a", "e", "i", "o", "u", "ai", "au", "ea", "ee", "ia", "ie", "oa", "oo", "ou", "ue"
        ];

        /// <inheritdoc />
        public GeneratedPassword Generate(PasswordSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var sets = PasswordCharsets.SelectedSets(spec.Characters)
                .Select(set => PasswordCharsets.Set(set, spec.ExcludeAmbiguous))
                .ToArray();

            var alphabet = string.Concat(sets);
            var buffer = new char[spec.Length];
            var guaranteed = 0;
            var entropyBits = 0d;

            // One character from every selected set first, so the value satisfies the usual policy
            // checks. Those positions are drawn from a smaller set, so they are counted separately and
            // the shuffle that follows is not counted at all: the reported entropy stays a lower bound.
            if (spec.RequireEachSet)
            {
                foreach (var set in sets)
                {
                    buffer[guaranteed++] = set[RandomNumberGenerator.GetInt32(set.Length)];
                    entropyBits += PasswordStrength.EntropyBits(1, set.Length);
                }
            }

            var remaining = spec.Length - guaranteed;

            if (remaining > 0)
            {
                RandomNumberGenerator.GetItems<char>(alphabet, buffer.AsSpan(guaranteed));
                entropyBits += PasswordStrength.EntropyBits(remaining, alphabet.Length);
            }

            RandomNumberGenerator.Shuffle<char>(buffer);

            var value = new string(buffer);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));

            var warnings = new List<string>();

            if (spec.Characters == PasswordCharacters.Digits)
            {
                warnings.Add(
                    "A value made of digits alone is far easier to guess than one that mixes character "
                    + "sets. Use it only where nothing else is accepted.");
            }

            return Describe(
                value,
                entropyBits,
                spec.Describe(),
                warnings);
        }

        /// <inheritdoc />
        public IReadOnlyList<GeneratedPassword> GenerateBulk(BulkPasswordSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var generated = new GeneratedPassword[spec.Count];

            for (var index = 0; index < generated.Length; index++)
            {
                // Each password is generated independently: no shared buffer, no derived value.
                generated[index] = Generate(spec.Password);
            }

            return generated;
        }

        /// <inheritdoc />
        public GeneratedPassword GeneratePassphrase(PassphraseSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var words = RandomNumberGenerator.GetItems<string>(Wordlist.Choices, spec.Words);
            var entropyBits = PasswordStrength.EntropyBits(spec.Words, Wordlist.Count);

            if (spec.Capitalize)
            {
                for (var index = 0; index < words.Length; index++)
                {
                    words[index] = Capitalize(words[index]);
                }
            }

            // Capitalisation is applied to every word, so it adds no entropy and is not counted.
            var value = string.Join(spec.Separator, words);
            var composition = $"{spec.Words} words from a {Wordlist.Count} word list";

            if (spec.IncludeNumber)
            {
                value += RandomCharacter(PasswordCharsets.Digits);
                entropyBits += PasswordStrength.EntropyBits(1, PasswordCharsets.Digits.Length);
                composition += ", one digit";
            }

            if (spec.IncludeSymbol)
            {
                value += RandomCharacter(PasswordCharsets.Symbols);
                entropyBits += PasswordStrength.EntropyBits(1, PasswordCharsets.Symbols.Length);
                composition += ", one symbol";
            }

            return Describe(value, entropyBits, composition);
        }

        /// <inheritdoc />
        public GeneratedPassword GeneratePronounceable(PronounceableSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var consonants = RandomNumberGenerator.GetItems<string>(Consonants, spec.Syllables);
            var vowels = RandomNumberGenerator.GetItems<string>(Vowels, spec.Syllables);

            var value = string.Concat(consonants.Zip(vowels, (consonant, vowel) => consonant + vowel));

            var entropyBits =
                PasswordStrength.EntropyBits(spec.Syllables, Consonants.Length)
                + PasswordStrength.EntropyBits(spec.Syllables, Vowels.Length);

            var composition =
                $"{spec.Syllables} syllables, each a consonant sound from {Consonants.Length} and a vowel "
                + $"sound from {Vowels.Length}";

            if (spec.Capitalize)
            {
                value = Capitalize(value);
            }

            if (spec.IncludeNumber)
            {
                value += RandomCharacter(PasswordCharsets.Digits);
                entropyBits += PasswordStrength.EntropyBits(1, PasswordCharsets.Digits.Length);
                composition += ", one digit";
            }

            return Describe(
                value,
                entropyBits,
                composition,
                [
                    "A pronounceable value trades strength for readability: it carries far less entropy "
                    + "than a random value of the same length."
                ]);
        }

        /// <inheritdoc />
        public GeneratedPassword GeneratePin(PinSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var digits = new char[spec.Length];
            RandomNumberGenerator.GetItems<char>(PasswordCharsets.Digits, digits.AsSpan());

            var value = new string(digits);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(digits.AsSpan()));

            return Describe(
                value,
                PasswordStrength.EntropyBits(spec.Length, PasswordCharsets.Digits.Length),
                $"{spec.Length} digits (10 character alphabet)",
                [
                    "A PIN is weak by construction. Rely on the device limiting how many attempts are "
                    + "allowed, and use a password wherever one is accepted."
                ]);
        }

        /// <inheritdoc />
        public GeneratedPassword GenerateUsername(UsernameSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var words = RandomNumberGenerator.GetItems<string>(Wordlist.Choices, spec.Words);
            var entropyBits = PasswordStrength.EntropyBits(spec.Words, Wordlist.Count);

            if (spec.Capitalize)
            {
                for (var index = 0; index < words.Length; index++)
                {
                    words[index] = Capitalize(words[index]);
                }
            }

            var value = string.Join(spec.Separator, words);
            var composition = $"{spec.Words} words from a {Wordlist.Count} word list";

            if (spec.IncludeNumber)
            {
                // Two digits, so the suffix reads as a number rather than as a stray digit.
                value += RandomNumberGenerator.GetInt32(10, 100).ToString(CultureInfo.InvariantCulture);
                entropyBits += PasswordStrength.EntropyBits(1, 90);
                composition += ", a two digit number";
            }

            return Describe(
                value,
                entropyBits,
                composition,
                [
                    "A username is a public identifier, not a secret. Do not treat it as one, and pair it "
                    + "with a separately generated password."
                ],
                adviseOnWeakness: false);
        }

        /// <summary>
        /// Wraps a generated value with the figures that describe it, and attaches the standard advisory
        /// when the value is too weak to be relied on as a password.
        /// </summary>
        /// <param name="value">The generated value.</param>
        /// <param name="entropyBits">Entropy of the generation process, before rounding.</param>
        /// <param name="composition">Description of what the value was built from.</param>
        /// <param name="warnings">Advisories specific to this kind of value.</param>
        /// <param name="adviseOnWeakness">
        /// Whether to add the low-entropy advisory. Turned off for values that are not secrets.
        /// </param>
        /// <remarks>
        /// The strength label is derived from the rounded figure that is reported, so a response can
        /// never show a number and a label that disagree.
        /// </remarks>
        private static GeneratedPassword Describe(
            string value,
            double entropyBits,
            string composition,
            IReadOnlyList<string>? warnings = null,
            bool adviseOnWeakness = true)
        {
            var rounded = PasswordStrength.Round(entropyBits);
            var advisories = new List<string>();

            if (warnings is not null)
            {
                advisories.AddRange(warnings);
            }

            if (adviseOnWeakness && rounded < PasswordStrength.AdvisoryThresholdBits)
            {
                var bits = rounded.ToString("0.#", CultureInfo.InvariantCulture);
                var threshold = PasswordStrength.AdvisoryThresholdBits.ToString("0", CultureInfo.InvariantCulture);

                advisories.Add(
                    $"About {bits} bits of entropy, which is below the {threshold} bits worth relying on "
                    + "for an account password. Increase the length, add character sets, or use more words.");
            }

            return new GeneratedPassword
            {
                Value = value,
                Length = value.Length,
                EntropyBits = rounded,
                Strength = PasswordStrength.Describe(rounded),
                Composition = composition,
                Warnings = advisories
            };
        }

        /// <summary>Picks one character from a set.</summary>
        /// <param name="characters">The set to pick from.</param>
        private static char RandomCharacter(string characters) =>
            characters[RandomNumberGenerator.GetInt32(characters.Length)];

        /// <summary>Upper-cases the first character of a word, leaving the rest untouched.</summary>
        /// <param name="word">A non-empty word.</param>
        private static string Capitalize(string word) =>
            char.ToUpperInvariant(word[0]) + word[1..];
    }
}
