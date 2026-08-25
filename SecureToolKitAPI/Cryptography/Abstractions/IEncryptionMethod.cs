namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>Encrypts a plaintext message using a compatible generated key.</summary>
    public interface IEncryptor : ICryptographicMethod
    {
        /// <summary>
        /// Encrypts <paramref name="plainText"/>.
        /// </summary>
        /// <param name="key">Base64 key material compatible with this method.</param>
        /// <param name="plainText">UTF-8 message to protect.</param>
        /// <exception cref="CryptographicRequestException">The key or message is not valid for this method.</exception>
        EncryptionResult Encrypt(string key, string plainText);
    }

    /// <summary>Decrypts an envelope produced by the matching <see cref="IEncryptor"/>.</summary>
    public interface IDecryptor : ICryptographicMethod
    {
        /// <summary>
        /// Decrypts <paramref name="encryptedMessage"/>.
        /// </summary>
        /// <param name="key">Base64 key material compatible with this method.</param>
        /// <param name="encryptedMessage">Base64 envelope produced by this method's encryptor.</param>
        /// <exception cref="CryptographicRequestException">The key or envelope is not valid for this method.</exception>
        string Decrypt(string key, string encryptedMessage);
    }

    /// <summary>
    /// A paired encryption/decryption implementation. Both directions live in one type so that the
    /// envelope layout and key handling cannot drift apart between encryption and decryption.
    /// </summary>
    public interface IEncryptionMethod : IEncryptor, IDecryptor
    {
        /// <summary>Description of the key material this method expects.</summary>
        string KeyFormat { get; }

        /// <summary>Documented byte layout of the envelope this method produces and consumes.</summary>
        string EnvelopeLayout { get; }
    }
}
