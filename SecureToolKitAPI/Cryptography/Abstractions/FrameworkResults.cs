namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Result of generating the one secret a framework asks for: a Django <c>SECRET_KEY</c>, a Flask
    /// <c>SECRET_KEY</c> or a Laravel <c>APP_KEY</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Value"/> is secret material. It must never be logged, cached or echoed anywhere other
    /// than the response to the caller that asked for it.
    /// </para>
    /// <para>
    /// Everything else describes the value without revealing it — <see cref="Setting"/> names where it
    /// belongs and <see cref="Composition"/> reports how many bits went in and how they were rendered — so
    /// those members are safe to surface in documentation and in logs.
    /// </para>
    /// </remarks>
    public sealed record GeneratedFrameworkKey
    {
        /// <summary>The framework this key was generated for, for example <c>Django</c>.</summary>
        public required string Framework { get; init; }

        /// <summary>
        /// The configuration name the value belongs under, for example <c>SECRET_KEY</c> or
        /// <c>APP_KEY</c>. Not secret; it is the same for every key of this kind.
        /// </summary>
        public required string Setting { get; init; }

        /// <summary>The generated value, including any prefix the framework requires. Secret.</summary>
        public required string Value { get; init; }

        /// <summary>Number of characters in <see cref="Value"/>.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of the generation process in bits, computed from how many choices were made and how
        /// large the set was that each came from — never by inspecting the value.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>, for example <c>Very strong</c>.</summary>
        public required string Strength { get; init; }

        /// <summary>
        /// Description of how the value was built, for example
        /// <c>256 random bits, hexadecimal</c>. Never contains the value itself.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>
        /// The specific shape that was asked for, when the framework has one — the Laravel cipher the key
        /// was sized for. Not secret.
        /// </summary>
        public string? Kind { get; init; }

        /// <summary>Advisories about how the value must be stored and what rotating it costs.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>One named framework secret: the constant it is defined as, and its value.</summary>
    /// <remarks>
    /// <see cref="Value"/> is secret material. <see cref="Name"/> is fixed by the framework and is not.
    /// </remarks>
    public sealed record FrameworkSalt
    {
        /// <summary>The constant this value is defined as, for example <c>AUTH_KEY</c>. Not secret.</summary>
        public required string Name { get; init; }

        /// <summary>The generated value. Secret.</summary>
        public required string Value { get; init; }
    }

    /// <summary>
    /// Result of generating the set of authentication keys and salts a WordPress installation needs in its
    /// <c>wp-config.php</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every value in <see cref="Salts"/> is secret material, and so is <see cref="Configuration"/>, which
    /// contains all of them. None of it may be logged, cached or echoed anywhere other than the response to
    /// the caller that asked for it.
    /// </para>
    /// <para>
    /// The values are generated independently of one another, so one of them leaking says nothing about the
    /// rest. That is the reason WordPress asks for eight rather than one.
    /// </para>
    /// </remarks>
    public sealed record GeneratedFrameworkSalts
    {
        /// <summary>The framework these values were generated for.</summary>
        public required string Framework { get; init; }

        /// <summary>The named values, in the order WordPress lists them. Each value is secret.</summary>
        public required IReadOnlyList<FrameworkSalt> Salts { get; init; }

        /// <summary>How many values were generated.</summary>
        public required int Count { get; init; }

        /// <summary>Number of characters in each value.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of each individual value in bits. The set as a whole carries this many bits times
        /// <see cref="Count"/>, because the values are drawn independently.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/> for a single value.</summary>
        public required string Strength { get; init; }

        /// <summary>
        /// Description of how each value was built. Never contains any of the values themselves.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>
        /// The block to paste into <c>wp-config.php</c>, with every value already quoted. Secret, because
        /// it contains all of them.
        /// </summary>
        public required string Configuration { get; init; }

        /// <summary>Advisories about how these values must be handled and what replacing them costs.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
