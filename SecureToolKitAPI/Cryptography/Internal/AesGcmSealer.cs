using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Thin wrapper over <see cref="AesGcm"/> shared by the AES-GCM and ECDH hybrid methods so the
    /// nonce, tag and associated-data handling exists in exactly one place.
    /// </summary>
    internal static class AesGcmSealer
    {
        /// <summary>AES-GCM nonce length in bytes (96 bits, the recommended size).</summary>
        internal const int NonceLength = 12;

        /// <summary>AES-GCM authentication tag length in bytes (128 bits, the maximum).</summary>
        internal const int TagLength = 16;

        /// <summary>Valid AES key lengths in bytes.</summary>
        internal static readonly int[] ValidKeyLengths = { 16, 24, 32 };

        /// <summary>Validates an AES key length, reporting a safe error without echoing the key.</summary>
        internal static void EnsureValidKeyLength(byte[] key)
        {
            if (Array.IndexOf(ValidKeyLengths, key.Length) < 0)
            {
                throw new CryptographicRequestException(
                    "The supplied AES key must be 16, 24 or 32 bytes (128, 192 or 256 bits) once Base64 decoded.");
            }
        }

        /// <summary>Encrypts with a freshly generated random nonce.</summary>
        /// <param name="key">Raw AES key.</param>
        /// <param name="plainText">Message bytes; may be empty.</param>
        /// <param name="associatedData">Data authenticated but not encrypted.</param>
        /// <param name="nonce">Receives the generated nonce.</param>
        /// <param name="tag">Receives the authentication tag.</param>
        /// <returns>The ciphertext.</returns>
        internal static byte[] Seal(
            byte[] key,
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> associatedData,
            out byte[] nonce,
            out byte[] tag)
        {
            nonce = RandomNumberGenerator.GetBytes(NonceLength);
            tag = new byte[TagLength];
            var cipherText = new byte[plainText.Length];

            using var aesGcm = new AesGcm(key, TagLength);
            aesGcm.Encrypt(nonce, plainText, cipherText, tag, associatedData);

            return cipherText;
        }

        /// <summary>
        /// Verifies the tag and decrypts. Any authentication or padding failure is reported as a
        /// single generic error so nothing about the cause is leaked to the caller.
        /// </summary>
        internal static byte[] Open(
            byte[] key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> cipherText,
            ReadOnlySpan<byte> associatedData)
        {
            var plainText = new byte[cipherText.Length];

            try
            {
                using var aesGcm = new AesGcm(key, TagLength);
                aesGcm.Decrypt(nonce, cipherText, tag, plainText, associatedData);
            }
            catch (CryptographicException)
            {
                throw new CryptographicRequestException(
                    "Decryption failed. The key is not correct for this message, or the encrypted message has been altered.");
            }

            return plainText;
        }
    }
}
