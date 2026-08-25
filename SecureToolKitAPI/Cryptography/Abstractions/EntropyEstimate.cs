namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// How much entropy a value of a given length, drawn from a given alphabet, would carry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This figure is exact, unlike the estimate a strength check can make, because it describes the way a
    /// value is chosen rather than a value that already exists. It holds only if every character really is
    /// drawn independently and uniformly; a value a person invented to fit the same pattern carries far
    /// less.
    /// </para>
    /// <para>
    /// No crack time is reported. That would need an assumed guess rate, and the honest range spans several
    /// orders of magnitude depending on the hash function, the hardware and whether the attack is online or
    /// offline — a single number would be a guess dressed up as a measurement.
    /// </para>
    /// </remarks>
    public sealed record EntropyEstimate
    {
        /// <summary>Number of characters described.</summary>
        public required int Count { get; init; }

        /// <summary>Number of symbols each character is drawn from.</summary>
        public required int AlphabetSize { get; init; }

        /// <summary>Entropy per character, in bits, rounded to one decimal place.</summary>
        public required double EntropyBitsPerCharacter { get; init; }

        /// <summary>Total entropy, in bits, rounded to one decimal place.</summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language strength for <see cref="EntropyBits"/>.</summary>
        public required string Strength { get; init; }

        /// <summary>What the alphabet consists of.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Base ten logarithm of the number of possible values. A logarithm because the count itself
        /// exceeds every numeric type well before the interesting sizes.
        /// </summary>
        public required double GuessesLog10 { get; init; }

        /// <summary>What this figure assumes, and when it does not hold.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
