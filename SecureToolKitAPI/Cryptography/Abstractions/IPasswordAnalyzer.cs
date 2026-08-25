namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Answers questions about password strength: what a supplied password appears to be worth, and what a
    /// password built to a given shape would be worth.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two are not the same kind of answer. <see cref="Estimate"/> is arithmetic on a described choice
    /// and is exact. <see cref="Analyze"/> looks at a value that already exists and can only ever produce
    /// an upper bound, because entropy lives in how a value was chosen and that information is gone by the
    /// time the value is a string.
    /// </para>
    /// <para>
    /// Implementations must not log, store, cache or echo the password they are given, must not include any
    /// part of it in the result, and must not report anything that would narrow it down for someone reading
    /// the response. Analysis is pure computation on the supplied characters and nothing else.
    /// </para>
    /// </remarks>
    public interface IPasswordAnalyzer
    {
        /// <summary>
        /// Assesses a password that was supplied rather than generated.
        /// </summary>
        /// <param name="password">The password to assess. Neither logged nor retained.</param>
        /// <returns>An upper bound on its strength, and what lowered the estimate.</returns>
        /// <exception cref="CryptographicRequestException">
        /// The password is missing, empty, or longer than can be assessed.
        /// </exception>
        PasswordAssessment Analyze(string? password);

        /// <summary>
        /// Works out how much entropy a value of a given length over a given alphabet would carry.
        /// </summary>
        /// <param name="spec">Length and alphabet.</param>
        /// <returns>The entropy the described choice produces.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        EntropyEstimate Estimate(EntropySpec spec);
    }
}
