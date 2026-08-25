using System.Globalization;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Recovery
{
    /// <summary>
    /// Generates account recovery credentials: single-use backup codes and a standalone recovery key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every character is drawn with <see cref="System.Security.Cryptography.RandomNumberGenerator"/>
    /// through <see cref="SecretText.Sample"/>, independently and uniformly, so the reported entropy is
    /// what the value actually carries. Nothing is derived from anything else: one code says nothing about
    /// the next.
    /// </para>
    /// <para>
    /// Nothing generated here is logged, cached or stored. The generator holds no state, which is why it is
    /// registered as a singleton.
    /// </para>
    /// <para>
    /// The grouping separators are presentation only and carry no entropy, so they are excluded from every
    /// figure reported.
    /// </para>
    /// </remarks>
    public sealed class RecoveryGenerator : IRecoveryGenerator
    {
        /// <summary>
        /// Bits below which a recovery key is called out as too weak. Higher than the threshold used for
        /// passwords because a recovery key usually faces an offline attack with no rate limit and no
        /// second factor behind it.
        /// </summary>
        private const double RecoveryKeyThresholdBits = 100d;

        /// <summary>The character that separates groups. Presentation only; carries no entropy.</summary>
        private const char GroupSeparator = '-';

        /// <inheritdoc />
        public GeneratedBackupCodes GenerateBackupCodes(BackupCodeSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var alphabet = SecretText.Alphabet(spec.Format);
            var codes = new string[spec.Count];

            for (var index = 0; index < codes.Length; index++)
            {
                // Drawn per code rather than sliced out of one long draw, so no relationship exists
                // between codes even in principle.
                codes[index] = Group(SecretText.Sample(alphabet, spec.Length), spec.GroupSize);
            }

            var entropyBits = PasswordStrength.Round(
                PasswordStrength.EntropyBits(spec.Length, alphabet.Length));

            return new GeneratedBackupCodes
            {
                Codes = codes,
                Length = spec.Length,
                EntropyBitsPerCode = entropyBits,
                Strength = PasswordStrength.Describe(entropyBits),
                Composition = Composition(spec.Length, spec.Describe(), spec.GroupSize),
                Warnings = BackupCodeAdvice(spec, entropyBits)
            };
        }

        /// <inheritdoc />
        public GeneratedRecoveryKey GenerateRecoveryKey(RecoveryKeySpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var alphabet = SecretText.Alphabet(spec.Format);
            var characters = spec.Characters;

            var entropyBits = PasswordStrength.Round(
                PasswordStrength.EntropyBits(characters, alphabet.Length));

            return new GeneratedRecoveryKey
            {
                Value = Group(SecretText.Sample(alphabet, characters), spec.GroupSize),
                Characters = characters,
                Groups = spec.Groups,
                EntropyBits = entropyBits,
                Strength = PasswordStrength.Describe(entropyBits),
                Composition = Composition(characters, spec.Describe(), spec.GroupSize),
                Warnings = RecoveryKeyAdvice(entropyBits)
            };
        }

        /// <summary>
        /// Breaks a value into fixed-size groups separated by <see cref="GroupSeparator"/>, so it can be
        /// read off a screen and typed back without losing the place.
        /// </summary>
        /// <param name="value">The value to break up.</param>
        /// <param name="groupSize">Characters per group; zero or a size covering the whole value leaves it alone.</param>
        private static string Group(string value, int groupSize)
        {
            if (groupSize <= 0 || groupSize >= value.Length)
            {
                return value;
            }

            var groups = new List<string>((value.Length + groupSize - 1) / groupSize);

            for (var start = 0; start < value.Length; start += groupSize)
            {
                groups.Add(value.Substring(start, Math.Min(groupSize, value.Length - start)));
            }

            return string.Join(GroupSeparator, groups);
        }

        /// <summary>Describes what was generated, without revealing any of it.</summary>
        /// <param name="characters">Characters of randomness, excluding separators.</param>
        /// <param name="alphabet">Description of the alphabet drawn from.</param>
        /// <param name="groupSize">Characters per group, or zero when the value is unbroken.</param>
        private static string Composition(int characters, string alphabet, int groupSize)
        {
            var description = $"{characters} characters drawn from {alphabet}";

            return groupSize > 0 && groupSize < characters
                ? $"{description}, written in groups of {groupSize}"
                : description;
        }

        /// <summary>
        /// What a caller has to do for backup codes of this strength to actually be safe.
        /// </summary>
        /// <param name="spec">The options the codes were generated from.</param>
        /// <param name="entropyBits">Entropy of one code, already rounded.</param>
        private static IReadOnlyList<string> BackupCodeAdvice(BackupCodeSpec spec, double entropyBits)
        {
            var bits = entropyBits.ToString("0.#", CultureInfo.InvariantCulture);

            var advice = new List<string>
            {
                "Each code is single use. Whatever accepts these must invalidate a code the moment it is "
                + "used and must rate-limit attempts, or a code that leaks stays usable indefinitely.",
                "Store these the way you store a password: hashed with a password-hashing function, never "
                + "in plain text and never in a log.",
                $"About {bits} bits per code, which is deliberately less than a password carries. A code "
                + "short enough to transcribe by hand is only safe behind the single-use and rate-limiting "
                + "rules above.",
                "The codes are returned once. This API does not store them and cannot produce them again."
            };

            if (spec.Format == BackupCodeFormat.Numeric)
            {
                advice.Add(
                    "Digits alone carry about 3.3 bits per character against 5 for the alphanumeric "
                    + "format, so a numeric code needs roughly half again the length to match it.");
            }

            return advice;
        }

        /// <summary>
        /// What a caller has to do for a recovery key to be worth what it protects.
        /// </summary>
        /// <param name="entropyBits">Entropy of the key, already rounded.</param>
        private static IReadOnlyList<string> RecoveryKeyAdvice(double entropyBits)
        {
            var advice = new List<string>
            {
                "This key restores access on its own, so it is worth as much as the account behind it. "
                + "Keep it offline or in a password manager, and never in the same place as the password "
                + "it recovers.",
                "Ignore the separators when verifying, and compare case-insensitively, so someone typing "
                + "the key back by hand is not locked out over punctuation.",
                "The key is returned once. This API does not store it and cannot produce it again."
            };

            if (entropyBits < RecoveryKeyThresholdBits)
            {
                var bits = entropyBits.ToString("0.#", CultureInfo.InvariantCulture);
                var threshold = RecoveryKeyThresholdBits.ToString("0", CultureInfo.InvariantCulture);

                advice.Add(
                    $"About {bits} bits, below the {threshold} bits worth relying on for a credential that "
                    + "is usually attacked offline with nothing else standing in the way. Add groups, "
                    + "lengthen them, or use the alphanumeric format.");
            }

            return advice;
        }
    }
}
