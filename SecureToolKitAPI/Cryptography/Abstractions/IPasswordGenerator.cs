namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates human-facing secrets: passwords, passphrases, pronounceable values, PINs, and the
    /// non-secret usernames that often accompany them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implementations must take every random choice from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> so that the entropy reported
    /// in <see cref="GeneratedPassword.EntropyBits"/> is real, and must validate their options before
    /// generating anything.
    /// </para>
    /// <para>
    /// This abstraction exists so the HTTP layer can offer these endpoints without knowing how any of
    /// the values are built, and so an alternative implementation — a different word list, a different
    /// alphabet policy — can be substituted without touching a controller.
    /// </para>
    /// </remarks>
    public interface IPasswordGenerator
    {
        /// <summary>
        /// Generates one random password.
        /// </summary>
        /// <param name="spec">Length, character sets and policy options.</param>
        /// <returns>The password together with its measured strength.</returns>
        /// <exception cref="CryptographicRequestException">The options are not valid.</exception>
        GeneratedPassword Generate(PasswordSpec spec);

        /// <summary>
        /// Generates several independent passwords that all share one set of options.
        /// </summary>
        /// <param name="spec">Batch size plus the options applied to every password.</param>
        /// <returns>The requested number of passwords, each generated independently.</returns>
        /// <exception cref="CryptographicRequestException">The options are not valid.</exception>
        IReadOnlyList<GeneratedPassword> GenerateBulk(BulkPasswordSpec spec);

        /// <summary>
        /// Generates a passphrase from words chosen independently from a fixed word list.
        /// </summary>
        /// <param name="spec">Word count, separator and decoration options.</param>
        /// <returns>The passphrase together with its measured strength.</returns>
        /// <exception cref="CryptographicRequestException">The options are not valid.</exception>
        GeneratedPassword GeneratePassphrase(PassphraseSpec spec);

        /// <summary>
        /// Generates a pronounceable value from alternating consonant and vowel sounds.
        /// </summary>
        /// <param name="spec">Syllable count and decoration options.</param>
        /// <returns>The value together with its measured strength, which is lower than a random string of the same length.</returns>
        /// <exception cref="CryptographicRequestException">The options are not valid.</exception>
        GeneratedPassword GeneratePronounceable(PronounceableSpec spec);

        /// <summary>
        /// Generates a numeric PIN.
        /// </summary>
        /// <param name="spec">The number of digits.</param>
        /// <returns>The PIN together with its measured strength and a warning that digits alone are weak.</returns>
        /// <exception cref="CryptographicRequestException">The options are not valid.</exception>
        GeneratedPassword GeneratePin(PinSpec spec);

        /// <summary>
        /// Suggests a username.
        /// </summary>
        /// <param name="spec">Word count, separator and decoration options.</param>
        /// <returns>
        /// The suggestion, with a warning that a username is a public identifier and not a secret.
        /// </returns>
        /// <exception cref="CryptographicRequestException">The options are not valid.</exception>
        GeneratedPassword GenerateUsername(UsernameSpec spec);
    }
}
