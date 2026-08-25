namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates salts: random bytes that make an input unique before it is hashed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A salt is not part of a key-generation method family — there is nothing to select between and no key
    /// size to validate against an algorithm — so it is generated through its own abstraction rather than
    /// through <see cref="IKeyGenerator"/> and the method registry.
    /// </para>
    /// <para>
    /// Implementations must draw every value from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> and must validate their options
    /// before drawing anything. A salt is not secret, but implementations still have no reason to log,
    /// cache or store one.
    /// </para>
    /// </remarks>
    public interface ISaltGenerator
    {
        /// <summary>
        /// Generates a salt of the requested size.
        /// </summary>
        /// <param name="spec">Size and encoding.</param>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedSalt Generate(SaltSpec spec);
    }
}
