namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Result of a password, passphrase, PIN or username generation request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Value"/> is secret material: it must never be logged, cached or echoed anywhere
    /// other than the response to the caller that asked for it.
    /// </para>
    /// <para>
    /// The remaining members describe the value without revealing it, so they are safe to surface in
    /// documentation and in API responses.
    /// </para>
    /// </remarks>
    public sealed record GeneratedPassword
    {
        /// <summary>The generated value. Secret.</summary>
        public required string Value { get; init; }

        /// <summary>Number of characters in <see cref="Value"/>.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Shannon entropy of the generation process in bits, computed from the alphabet and the
        /// number of independently chosen elements rather than by inspecting the value.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>
        /// Plain-language strength label derived from <see cref="EntropyBits"/>, for example
        /// <c>Strong</c>.
        /// </summary>
        public required string Strength { get; init; }

        /// <summary>
        /// Description of what the value was built from, for example
        /// <c>lowercase, uppercase, digits, symbols (84 character alphabet)</c>. Never contains the
        /// value itself.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>Non-fatal advisories, for example that a digits-only value is easy to guess.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
