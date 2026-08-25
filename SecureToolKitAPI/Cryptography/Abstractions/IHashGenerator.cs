namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Computes message digests, and describes the hash functions it will compute.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the one part of the API that produces no secret and consumes no key. A digest is a one-way
    /// fingerprint: the same message always gives the same digest, there is nothing to decrypt, and the
    /// message cannot be recovered from the result. Implementations must say so in their warnings, because
    /// hashing is the operation most often mistaken for encryption.
    /// </para>
    /// <para>
    /// Password hashing is not in scope here and must not be added to it. bcrypt, scrypt, Argon2 and PBKDF2
    /// are deliberately slow and take a per-password salt; the functions behind this interface are deliberately
    /// fast, which is exactly what makes them unsuitable for storing a password.
    /// </para>
    /// <para>
    /// Implementations must use the .NET one-shot hashing APIs rather than implementing any hash function
    /// themselves, must be stateless and safe to share, and must never log or retain the caller's message.
    /// </para>
    /// </remarks>
    public interface IHashGenerator
    {
        /// <summary>Computes the digest of a message.</summary>
        /// <param name="spec">
        /// The function, the message, how to read it and how to render the result. Validated before anything
        /// is hashed.
        /// </param>
        /// <returns>
        /// The digest and the figures describing it. Contains no secret and never contains the message.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">
        /// An option is unsupported, the message is missing, or the message is malformed for the chosen input
        /// format.
        /// </exception>
        ComputedHash ComputeHash(HashSpec spec);

        /// <summary>Lists the hash functions this API will compute.</summary>
        /// <returns>The catalogue, in a stable order. Contains no caller data.</returns>
        IReadOnlyList<HashAlgorithmInfo> HashAlgorithms();
    }
}
