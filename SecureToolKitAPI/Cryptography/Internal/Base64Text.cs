using System.Text;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Conversion helpers shared by the cryptographic methods. Failures are reported through
    /// <see cref="CryptographicRequestException"/> with messages that never echo the supplied value.
    /// </summary>
    internal static class Base64Text
    {
        private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>Decodes required Base64 input, reporting a safe error when it is missing or malformed.</summary>
        /// <param name="value">Base64 text supplied by the caller.</param>
        /// <param name="description">Caller-facing name of the value, for example "key".</param>
        internal static byte[] Decode(string? value, string description)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new CryptographicRequestException($"The {description} is required.");
            }

            try
            {
                return Convert.FromBase64String(value);
            }
            catch (FormatException)
            {
                throw new CryptographicRequestException($"The {description} is not valid Base64.");
            }
        }

        /// <summary>
        /// Attempts to decode Base64 input without throwing, for a caller that reports the failure in its
        /// own words rather than as a decoding error.
        /// </summary>
        /// <param name="value">Base64 text supplied by the caller.</param>
        /// <param name="decoded">The decoded bytes, or an empty array when the text is not valid Base64.</param>
        /// <returns><c>true</c> when the text was decoded.</returns>
        /// <remarks>
        /// <see cref="Decode"/> is the right choice where the value is a key or a ciphertext, because a
        /// malformed one is a bad request either way. This overload exists for input that is being examined
        /// rather than used, where a <see cref="FormatException"/> escaping as a server error would be the
        /// wrong answer.
        /// </remarks>
        internal static bool TryDecode(string? value, out byte[] decoded)
        {
            decoded = [];

            if (value is null)
            {
                return false;
            }

            // Four Base64 characters carry three bytes, and any whitespace only lowers that, so this is an
            // upper bound on the decoded size.
            var buffer = new byte[value.Length / 4 * 3];

            if (!Convert.TryFromBase64String(value, buffer, out var written))
            {
                return false;
            }

            decoded = buffer.Length == written ? buffer : buffer[..written];

            return true;
        }

        /// <summary>Encodes bytes as Base64.</summary>
        internal static string Encode(ReadOnlySpan<byte> value) => Convert.ToBase64String(value);

        /// <summary>
        /// Encodes a message as UTF-8 bytes. An empty message is valid; a missing one is not.
        /// </summary>
        internal static byte[] ToUtf8(string? message)
        {
            if (message is null)
            {
                throw new CryptographicRequestException("The message is required.");
            }

            return StrictUtf8.GetBytes(message);
        }

        /// <summary>
        /// Decodes authenticated plaintext back to text, rejecting byte sequences that are not valid UTF-8.
        /// </summary>
        internal static string FromUtf8(ReadOnlySpan<byte> plainText)
        {
            try
            {
                return StrictUtf8.GetString(plainText);
            }
            catch (DecoderFallbackException)
            {
                throw new CryptographicRequestException(
                    "The decrypted content is not a valid UTF-8 message.");
            }
        }
    }
}
