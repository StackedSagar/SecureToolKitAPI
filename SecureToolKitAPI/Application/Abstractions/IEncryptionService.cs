using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application.Abstractions
{
    /// <summary>
    /// Application service that selects an encryption method and delegates the cryptography to it.
    /// </summary>
    /// <remarks>
    /// Encryption and decryption are separate abstractions so that a caller of one is not coupled to
    /// the other, even though a single method implements both directions.
    /// </remarks>
    public interface IEncryptionService
    {
        /// <summary>All supported encryption methods, ordered by canonical name.</summary>
        IReadOnlyList<IEncryptionMethod> Methods { get; }

        /// <summary>
        /// Encrypts a message with a key compatible with the requested method.
        /// </summary>
        /// <param name="method">Canonical name or alias of the encryption method.</param>
        /// <param name="key">Base64 key material.</param>
        /// <param name="message">Message to encrypt.</param>
        /// <exception cref="CryptographicRequestException">
        /// The method is not supported, or the key or message is not valid for it.
        /// </exception>
        EncryptionOutcome Encrypt(string? method, string key, string message);
    }
}
