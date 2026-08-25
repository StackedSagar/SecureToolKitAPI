namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates the secrets a web framework asks for by name: a Django <c>SECRET_KEY</c>, a Flask
    /// <c>SECRET_KEY</c>, a Laravel <c>APP_KEY</c> and the set of WordPress authentication keys and salts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What separates these from a generic random string is that each one matches the shape the framework
    /// itself produces: the alphabet Django samples from, the length Laravel's configured cipher requires,
    /// the eight constants WordPress expects. Implementations must reproduce those shapes rather than
    /// substitute their own, because a value the framework rejects is worse than no value at all.
    /// </para>
    /// <para>
    /// Implementations must draw every value from <see cref="System.Security.Cryptography.RandomNumberGenerator"/>,
    /// must validate their options before drawing anything, and must report entropy computed from the
    /// generation process rather than guessed from the finished value.
    /// </para>
    /// <para>
    /// Nothing here derives one secret from another: every value returned is independent. Implementations
    /// must not log, cache or store any value they produce.
    /// </para>
    /// </remarks>
    public interface IFrameworkKeyGenerator
    {
        /// <summary>
        /// Generates a Django <c>SECRET_KEY</c>, sampled from Django's own alphabet.
        /// </summary>
        /// <param name="spec">The key length.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The length is outside the supported range.</exception>
        GeneratedFrameworkKey GenerateDjangoSecretKey(DjangoSecretKeySpec spec);

        /// <summary>
        /// Generates a Flask <c>SECRET_KEY</c>: random bytes rendered as text.
        /// </summary>
        /// <param name="spec">Size and encoding.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedFrameworkKey GenerateFlaskSecretKey(FlaskSecretKeySpec spec);

        /// <summary>
        /// Generates a Laravel <c>APP_KEY</c>, sized for the configured cipher and written with the
        /// <c>base64:</c> prefix Laravel expects.
        /// </summary>
        /// <param name="spec">The cipher the application is configured with.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The cipher is not supported.</exception>
        GeneratedFrameworkKey GenerateLaravelAppKey(LaravelAppKeySpec spec);

        /// <summary>
        /// Generates the eight WordPress authentication keys and salts, independently of one another, with
        /// the block to paste into <c>wp-config.php</c>.
        /// </summary>
        /// <param name="spec">The length of each value.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The length is outside the supported range.</exception>
        GeneratedFrameworkSalts GenerateWordPressSalts(WordPressSaltSpec spec);
    }
}
