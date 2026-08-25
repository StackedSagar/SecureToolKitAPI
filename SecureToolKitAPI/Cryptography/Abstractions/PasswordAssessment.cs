namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// What can be said about the strength of a password that was supplied rather than generated.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything here is an estimate, and an upper bound at that. Entropy is a property of how a value was
    /// chosen, not of the value itself: <c>correct-horse</c> and a random ten-character string can look
    /// alike to a checker and be worlds apart in practice. The figures below are what an attacker who knows
    /// only the shape of the password would have to try; one who guesses how it was made needs far less.
    /// </para>
    /// <para>
    /// Nothing here can tell whether a password has appeared in a breach, which is the single most useful
    /// thing to know about one. Checking that needs a breach corpus, which this API does not have.
    /// </para>
    /// <para>
    /// The password itself is never included in this result, never written to a log and never stored.
    /// <see cref="Findings"/> describes what was noticed without quoting any part of the value.
    /// </para>
    /// </remarks>
    public sealed record PasswordAssessment
    {
        /// <summary>Number of characters examined.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Estimated entropy in bits, rounded to one decimal place. An upper bound: it accounts for the
        /// patterns that were noticed and cannot account for the ones that were not.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language strength for <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the password appears to be built from, without quoting any of it.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Base ten logarithm of the number of guesses <see cref="EntropyBits"/> implies. A logarithm
        /// because the count itself exceeds every numeric type for a password of any real strength.
        /// </summary>
        public required double GuessesLog10 { get; init; }

        /// <summary>
        /// Observations that lowered the estimate — a repeated character, a sequence, a single character
        /// set. Each names the pattern, never the characters involved.
        /// </summary>
        public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();

        /// <summary>What to do about the findings, and what this check cannot tell you.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
