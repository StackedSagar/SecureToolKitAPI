namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates the secrets a developer needs when wiring up a service: API keys, JWT signing secrets,
    /// opaque OAuth values, the random values a WebAuthn registration needs, arbitrary random strings and
    /// Web Push VAPID key pairs.
    /// </summary>
    /// <remarks>
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
    public interface IDeveloperSecretGenerator
    {
        /// <summary>
        /// Generates an API key: random bytes rendered as text, optionally behind a recognisable prefix.
        /// </summary>
        /// <param name="spec">Size, encoding and prefix.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedSecret GenerateApiKey(ByteSecretSpec spec);

        /// <summary>
        /// Generates a symmetric secret for signing JSON Web Tokens, sized for the chosen HMAC algorithm.
        /// </summary>
        /// <param name="spec">Algorithm and encoding.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are not supported.</exception>
        GeneratedSecret GenerateJwtSecret(JwtSecretSpec spec);

        /// <summary>
        /// Generates an opaque OAuth 2.0 value — an access token, refresh token, client secret or
        /// authorization code — sized for how long that kind of value lives.
        /// </summary>
        /// <param name="spec">Kind, size and encoding.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedSecret GenerateOAuthToken(OAuthTokenSpec spec);

        /// <summary>
        /// Generates the random values a WebAuthn registration needs: a single-use challenge and an opaque
        /// user handle.
        /// </summary>
        /// <param name="spec">Sizes of the two values.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">A size is outside the supported range.</exception>
        GeneratedWebAuthnCredential GenerateWebAuthnCredential(WebAuthnSpec spec);

        /// <summary>
        /// Generates a random string of a requested length from a named or caller-supplied alphabet.
        /// </summary>
        /// <param name="spec">Length and alphabet.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedSecret GenerateRandomString(RandomStringSpec spec);

        /// <summary>
        /// Generates a VAPID key pair for Web Push.
        /// </summary>
        /// <returns>
        /// An ECDSA P-256 pair in both the raw Base64url form Web Push libraries use and the standard PEM
        /// forms. There are no options because RFC 8292 allows only this one curve.
        /// </returns>
        GeneratedVapidKey GenerateVapidKey();
    }
}
