namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Measures how hard a generated value is to guess, and turns that measurement into a label a
    /// caller can act on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Entropy is computed from the generation process — how many elements were chosen independently,
    /// and how large the set was that each was chosen from — never by inspecting the value itself.
    /// Guessing entropy from a finished string is guesswork; here the process is known exactly, so the
    /// number is real.
    /// </para>
    /// <para>
    /// Where a generator constrains its output, for example by guaranteeing one character from every
    /// selected set, the contributions are summed per element. That yields a conservative lower bound:
    /// the true entropy is slightly higher because the positions are also shuffled, and under-reporting
    /// is the safe direction to be wrong in.
    /// </para>
    /// </remarks>
    internal static class PasswordStrength
    {
        /// <summary>
        /// Entropy contributed by choosing <paramref name="count"/> elements independently and
        /// uniformly from a set of <paramref name="alphabetSize"/> elements.
        /// </summary>
        /// <param name="count">Number of independent choices.</param>
        /// <param name="alphabetSize">Number of possibilities per choice.</param>
        /// <returns>The contribution in bits, or zero when there is no real choice to make.</returns>
        internal static double EntropyBits(int count, int alphabetSize) =>
            count <= 0 || alphabetSize <= 1
                ? 0d
                : count * Math.Log2(alphabetSize);

        /// <summary>Rounds an entropy figure for reporting, so responses do not carry false precision.</summary>
        /// <param name="entropyBits">Entropy in bits.</param>
        internal static double Round(double entropyBits) => Math.Round(entropyBits, 1);

        /// <summary>
        /// Plain-language label for an entropy figure.
        /// </summary>
        /// <param name="entropyBits">Entropy in bits.</param>
        /// <returns>
        /// One of <c>Very weak</c>, <c>Weak</c>, <c>Reasonable</c>, <c>Strong</c> or
        /// <c>Very strong</c>.
        /// </returns>
        /// <remarks>
        /// The thresholds follow the conventional reading of guessing entropy: below 28 bits a value
        /// falls to trivial offline guessing, 60 bits resists a determined offline attack on a properly
        /// hashed credential, and 128 bits is the level expected of a cryptographic key.
        /// </remarks>
        internal static string Describe(double entropyBits) => entropyBits switch
        {
            < 28d => "Very weak",
            < 36d => "Weak",
            < 60d => "Reasonable",
            < 128d => "Strong",
            _ => "Very strong"
        };

        /// <summary>
        /// Entropy below which a value should not be relied on as a password, used to decide whether to
        /// attach an advisory warning.
        /// </summary>
        internal const double AdvisoryThresholdBits = 60d;
    }
}
