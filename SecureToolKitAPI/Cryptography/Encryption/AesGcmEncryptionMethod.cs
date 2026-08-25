using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Encryption
{
    /// <summary>
    /// AES-GCM authenticated symmetric encryption. The same key encrypts and decrypts, and any
    /// modification of the envelope is detected by the authentication tag.
    /// </summary>
    public sealed class AesGcmEncryptionMethod : IEncryptionMethod
    {
        /// <inheritdoc />
        public string Name => "aes-gcm";

        /// <inheritdoc />
        public IReadOnlyCollection<string> Aliases => new[] { "aes", "aesgcm" };

        /// <inheritdoc />
        public string Description => "AES-GCM authenticated encryption using a shared symmetric key.";

        /// <inheritdoc />
        public string KeyFormat => "Base64 AES key of 128, 192 or 256 bits, as returned by /api/keygen/aes.";

        /// <inheritdoc />
        public string EnvelopeLayout =>
            "version(1) | methodId(1) | nonce(12) | tag(16) | ciphertext(n)";

        /// <inheritdoc />
        public EncryptionResult Encrypt(string key, string plainText)
        {
            var keyBytes = Base64Text.Decode(key, "key");
            AesGcmSealer.EnsureValidKeyLength(keyBytes);

            try
            {
                var cipherText = AesGcmSealer.Seal(
                    keyBytes,
                    Base64Text.ToUtf8(plainText),
                    ReadOnlySpan<byte>.Empty,
                    out var nonce,
                    out var tag);

                var payload = new byte[AesGcmSealer.NonceLength + AesGcmSealer.TagLength + cipherText.Length];
                nonce.CopyTo(payload, 0);
                tag.CopyTo(payload, AesGcmSealer.NonceLength);
                cipherText.CopyTo(payload, AesGcmSealer.NonceLength + AesGcmSealer.TagLength);

                return new EncryptionResult(
                    Base64Text.Encode(CryptoEnvelope.Wrap(EnvelopeMethodId.AesGcm, payload)),
                    new EncryptionParameters
                    {
                        Nonce = Base64Text.Encode(nonce),
                        AuthenticationTag = Base64Text.Encode(tag)
                    });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }

        /// <inheritdoc />
        public string Decrypt(string key, string encryptedMessage)
        {
            var keyBytes = Base64Text.Decode(key, "key");
            AesGcmSealer.EnsureValidKeyLength(keyBytes);

            try
            {
                var payload = CryptoEnvelope.Unwrap(
                    Base64Text.Decode(encryptedMessage, "encrypted message"),
                    EnvelopeMethodId.AesGcm);

                if (payload.Length < AesGcmSealer.NonceLength + AesGcmSealer.TagLength)
                {
                    throw new CryptographicRequestException("The encrypted message is malformed.");
                }

                var plainText = AesGcmSealer.Open(
                    keyBytes,
                    payload.Slice(0, AesGcmSealer.NonceLength),
                    payload.Slice(AesGcmSealer.NonceLength, AesGcmSealer.TagLength),
                    payload[(AesGcmSealer.NonceLength + AesGcmSealer.TagLength)..],
                    ReadOnlySpan<byte>.Empty);

                return Base64Text.FromUtf8(plainText);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }
    }
}
