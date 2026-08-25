using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application.Abstractions
{
    /// <summary>
    /// Application service that selects the decryption method matching an envelope and delegates the
    /// cryptography to it.
    /// </summary>
    public interface IDecryptionService
    {
        /// <summary>All supported decryption methods, ordered by canonical name.</summary>
        IReadOnlyList<IEncryptionMethod> Methods { get; }

        /// <summary>
        /// Decrypts an envelope with a key compatible with the requested method.
        /// </summary>
        /// <param name="method">Canonical name or alias of the decryption method.</param>
        /// <param name="key">Base64 key material.</param>
        /// <param name="encryptedMessage">Base64 envelope produced by the matching encryption method.</param>
        /// <exception cref="CryptographicRequestException">
        /// The method is not supported, or the key or envelope is not valid for it.
        /// </exception>
        DecryptionOutcome Decrypt(string? method, string key, string encryptedMessage);
    }
}
