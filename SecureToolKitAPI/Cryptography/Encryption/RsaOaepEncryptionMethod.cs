using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Encryption
{
    /// <summary>
    /// RSA-OAEP (SHA-256) asymmetric encryption: the public key encrypts, the matching private key
    /// decrypts. Message size is bounded by the key size, so large payloads should use a hybrid
    /// method such as <c>ecc-hillman</c> instead.
    /// </summary>
    public sealed class RsaOaepEncryptionMethod : IEncryptionMethod
    {
        private const int Sha256HashLength = 32;
        private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

        /// <inheritdoc />
        public string Name => "rsa-oaep";

        /// <inheritdoc />
        public IReadOnlyCollection<string> Aliases => new[] { "rsa", "rsaoaep" };

        /// <inheritdoc />
        public string Description => "RSA-OAEP with SHA-256. Encrypt with the public key, decrypt with the private key.";

        /// <inheritdoc />
        public string KeyFormat =>
            "Base64 RSA public key (PKCS#1 or SubjectPublicKeyInfo) to encrypt, private key (PKCS#1 or PKCS#8) to decrypt, "
            + $"minimum {KeyImport.MinimumRsaKeySizeBits} bits, as returned by /api/keygen/rsa.";

        /// <inheritdoc />
        public string EnvelopeLayout => "version(1) | methodId(1) | ciphertext(keySize/8)";

        /// <summary>
        /// Largest message, in bytes, that a key of the given size can encrypt under OAEP with SHA-256.
        /// </summary>
        /// <param name="keySizeBits">RSA modulus size in bits.</param>
        public static int MaxMessageLength(int keySizeBits) =>
            (keySizeBits / 8) - (2 * Sha256HashLength) - 2;

        /// <inheritdoc />
        public EncryptionResult Encrypt(string key, string plainText)
        {
            using var rsa = KeyImport.ImportRsaPublicKey(Base64Text.Decode(key, "key"));
            KeyImport.EnsureRsaKeySizeAllowed(rsa);

            var plainBytes = Base64Text.ToUtf8(plainText);
            var maxLength = MaxMessageLength(rsa.KeySize);

            if (plainBytes.Length > maxLength)
            {
                throw new CryptographicRequestException(
                    $"The message is too large for RSA-OAEP with a {rsa.KeySize}-bit key. "
                    + $"The limit is {maxLength} bytes of UTF-8 text; use a larger key or a hybrid method such as 'ecc-hillman'.");
            }

            byte[] cipherText;
            try
            {
                cipherText = rsa.Encrypt(plainBytes, Padding);
            }
            catch (CryptographicException)
            {
                throw new CryptographicRequestException(
                    "Encryption failed. The supplied RSA public key could not be used for RSA-OAEP encryption.");
            }

            return new EncryptionResult(
                Base64Text.Encode(CryptoEnvelope.Wrap(EnvelopeMethodId.RsaOaep, cipherText)),
                new EncryptionParameters());
        }

        /// <inheritdoc />
        public string Decrypt(string key, string encryptedMessage)
        {
            using var rsa = KeyImport.ImportRsaPrivateKey(Base64Text.Decode(key, "key"));
            KeyImport.EnsureRsaKeySizeAllowed(rsa);

            var cipherText = CryptoEnvelope.Unwrap(
                Base64Text.Decode(encryptedMessage, "encrypted message"),
                EnvelopeMethodId.RsaOaep);

            if (cipherText.Length == 0)
            {
                throw new CryptographicRequestException("The encrypted message is malformed.");
            }

            byte[] plainBytes;
            try
            {
                plainBytes = rsa.Decrypt(cipherText.ToArray(), Padding);
            }
            catch (CryptographicException)
            {
                throw new CryptographicRequestException(
                    "Decryption failed. The key is not correct for this message, or the encrypted message has been altered.");
            }

            return Base64Text.FromUtf8(plainBytes);
        }
    }
}
