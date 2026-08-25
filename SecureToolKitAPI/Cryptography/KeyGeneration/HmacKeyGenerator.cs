using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>Generates an HMAC secret for the <c>hmac-sha256</c> signature method.</summary>
    public sealed class HmacKeyGenerator : KeyGeneratorBase
    {
        /// <inheritdoc />
        public override string Name => "hmac";

        /// <inheritdoc />
        public override IReadOnlyCollection<string> Aliases => new[] { "hmac-sha256", "hmacsha256" };

        /// <inheritdoc />
        public override string Description => "Random secret for HMAC-SHA256 message authentication.";

        /// <inheritdoc />
        public override IReadOnlyCollection<int> SupportedKeySizes => new[] { 128, 256, 384, 512 };

        /// <inheritdoc />
        public override int DefaultKeySize => 256;

        /// <inheritdoc />
        protected override GeneratedKey GenerateCore(int keySizeBits) => new()
        {
            Algorithm = "HMAC-SHA256",
            KeySizeBits = keySizeBits,
            Key = Base64Text.Encode(RandomNumberGenerator.GetBytes(keySizeBits / 8)),
            KeyFormat = "Base64 encoded raw HMAC secret."
        };
    }
}
