using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Encryption
{
    /// <summary>
    /// Hybrid encryption using ECDH key agreement with AES-GCM (ECIES style), matching the
    /// <c>ecc-hillman</c> key pair. Encryption uses the recipient's public key together with a
    /// single-use ephemeral key pair; decryption uses the recipient's private key.
    /// </summary>
    /// <remarks>
    /// The AES key is derived as SHA-256 of the ECDH shared secret with a fixed context string
    /// appended, giving a 256-bit key regardless of curve. The ephemeral public key is carried in the
    /// envelope and is authenticated as AES-GCM associated data, binding the ciphertext to it.
    /// Unlike plain RSA this places no practical limit on message size.
    /// </remarks>
    public sealed class EcdhAesGcmEncryptionMethod : IEncryptionMethod
    {
        private const int EphemeralKeyLengthPrefix = 2;

        private static readonly byte[] ContextInfo =
            Encoding.UTF8.GetBytes("SecureToolKitAPI/ecc-hillman/v1");

        /// <inheritdoc />
        public string Name => "ecc-hillman";

        /// <inheritdoc />
        public IReadOnlyCollection<string> Aliases => new[] { "ecchillman", "ecdh", "ecdh-aes-gcm" };

        /// <inheritdoc />
        public string Description =>
            "Hybrid ECDH key agreement with AES-GCM. Encrypt with the recipient public key, decrypt with the private key.";

        /// <inheritdoc />
        public string KeyFormat =>
            "Base64 SubjectPublicKeyInfo EC public key to encrypt, PKCS#8 EC private key to decrypt, "
            + "on P-256, P-384 or P-521, as returned by /api/keygen/EccHillman.";

        /// <inheritdoc />
        public string EnvelopeLayout =>
            "version(1) | methodId(1) | ephemeralPublicKeyLength(2, big endian) | ephemeralPublicKey(SubjectPublicKeyInfo) "
            + "| nonce(12) | tag(16) | ciphertext(n)";

        /// <inheritdoc />
        public EncryptionResult Encrypt(string key, string plainText)
        {
            using var recipient = KeyImport.ImportEcdhPublicKey(Base64Text.Decode(key, "key"));
            using var ephemeral = ECDiffieHellman.Create(EcCurves.FromKeySize(recipient.KeySize));

            var ephemeralPublicKey = ephemeral.ExportSubjectPublicKeyInfo();
            var derivedKey = DeriveKey(ephemeral, recipient.PublicKey);

            try
            {
                var cipherText = AesGcmSealer.Seal(
                    derivedKey,
                    Base64Text.ToUtf8(plainText),
                    ephemeralPublicKey,
                    out var nonce,
                    out var tag);

                var payload = new byte[
                    EphemeralKeyLengthPrefix + ephemeralPublicKey.Length
                    + AesGcmSealer.NonceLength + AesGcmSealer.TagLength + cipherText.Length];

                BinaryPrimitives.WriteUInt16BigEndian(payload, (ushort)ephemeralPublicKey.Length);

                var offset = EphemeralKeyLengthPrefix;
                ephemeralPublicKey.CopyTo(payload, offset);
                offset += ephemeralPublicKey.Length;
                nonce.CopyTo(payload, offset);
                offset += AesGcmSealer.NonceLength;
                tag.CopyTo(payload, offset);
                offset += AesGcmSealer.TagLength;
                cipherText.CopyTo(payload, offset);

                return new EncryptionResult(
                    Base64Text.Encode(CryptoEnvelope.Wrap(EnvelopeMethodId.EcdhAesGcm, payload)),
                    new EncryptionParameters
                    {
                        Nonce = Base64Text.Encode(nonce),
                        AuthenticationTag = Base64Text.Encode(tag),
                        EphemeralPublicKey = Base64Text.Encode(ephemeralPublicKey)
                    });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedKey);
            }
        }

        /// <inheritdoc />
        public string Decrypt(string key, string encryptedMessage)
        {
            using var recipient = KeyImport.ImportEcdhPrivateKey(Base64Text.Decode(key, "key"));

            var payload = CryptoEnvelope.Unwrap(
                Base64Text.Decode(encryptedMessage, "encrypted message"),
                EnvelopeMethodId.EcdhAesGcm);

            if (payload.Length < EphemeralKeyLengthPrefix)
            {
                throw new CryptographicRequestException("The encrypted message is malformed.");
            }

            int ephemeralKeyLength = BinaryPrimitives.ReadUInt16BigEndian(payload);
            var fixedLength = EphemeralKeyLengthPrefix + ephemeralKeyLength
                + AesGcmSealer.NonceLength + AesGcmSealer.TagLength;

            if (ephemeralKeyLength == 0 || payload.Length < fixedLength)
            {
                throw new CryptographicRequestException("The encrypted message is malformed.");
            }

            var ephemeralPublicKey = payload.Slice(EphemeralKeyLengthPrefix, ephemeralKeyLength).ToArray();

            using var ephemeral = KeyImport.ImportEcdhPublicKey(ephemeralPublicKey);
            var derivedKey = DeriveKey(recipient, ephemeral.PublicKey);

            try
            {
                var offset = EphemeralKeyLengthPrefix + ephemeralKeyLength;

                var plainText = AesGcmSealer.Open(
                    derivedKey,
                    payload.Slice(offset, AesGcmSealer.NonceLength),
                    payload.Slice(offset + AesGcmSealer.NonceLength, AesGcmSealer.TagLength),
                    payload[fixedLength..],
                    ephemeralPublicKey);

                return Base64Text.FromUtf8(plainText);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedKey);
            }
        }

        /// <summary>
        /// Derives the 256-bit AES key from an ECDH agreement. Both sides compute the same value
        /// because the shared secret is identical in either direction.
        /// </summary>
        private static byte[] DeriveKey(ECDiffieHellman ownKey, ECDiffieHellmanPublicKey otherPartyPublicKey)
        {
            try
            {
                return ownKey.DeriveKeyFromHash(
                    otherPartyPublicKey,
                    HashAlgorithmName.SHA256,
                    secretPrepend: null,
                    secretAppend: ContextInfo);
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            {
                // Mismatched curves are reported differently by the platform key providers, so both
                // shapes are translated into the same safe message.
                throw new CryptographicRequestException(
                    "Key agreement failed. The supplied key does not match the curve used for this message.");
            }
        }
    }
}
