using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Signing
{
    /// <summary>
    /// HMAC-SHA256 message authentication using the shared secret from <c>/api/keygen/hmac</c>.
    /// The same secret produces and verifies the code, so it must be shared only with trusted parties.
    /// </summary>
    public sealed class HmacSha256SignatureMethod : ISignatureMethod
    {
        private const int MinimumSecretLengthBytes = 16;

        /// <inheritdoc />
        public string Name => "hmac-sha256";

        /// <inheritdoc />
        public IReadOnlyCollection<string> Aliases => new[] { "hmac", "hmacsha256" };

        /// <inheritdoc />
        public string Description => "HMAC-SHA256 authentication code using a shared secret.";

        /// <inheritdoc />
        public string SigningKeyFormat => "Base64 shared secret of at least 16 bytes, as returned by /api/keygen/hmac.";

        /// <inheritdoc />
        public string VerificationKeyFormat => "The same Base64 shared secret used to sign.";

        /// <inheritdoc />
        public string SignatureFormat => "Base64 32-byte HMAC-SHA256 code.";

        /// <inheritdoc />
        public string Sign(string key, string message)
        {
            var secret = ReadSecret(key);

            try
            {
                return Base64Text.Encode(HMACSHA256.HashData(secret, Base64Text.ToUtf8(message)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        /// <inheritdoc />
        public bool Verify(string key, string message, string signature)
        {
            var secret = ReadSecret(key);

            try
            {
                var provided = Base64Text.Decode(signature, "signature");
                var expected = HMACSHA256.HashData(secret, Base64Text.ToUtf8(message));

                // Constant-time comparison; also returns false when the lengths differ.
                return CryptographicOperations.FixedTimeEquals(expected, provided);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        private static byte[] ReadSecret(string key)
        {
            var secret = Base64Text.Decode(key, "key");

            if (secret.Length < MinimumSecretLengthBytes)
            {
                throw new CryptographicRequestException(
                    $"The supplied HMAC secret must be at least {MinimumSecretLengthBytes} bytes once Base64 decoded.");
            }

            return secret;
        }
    }
}
