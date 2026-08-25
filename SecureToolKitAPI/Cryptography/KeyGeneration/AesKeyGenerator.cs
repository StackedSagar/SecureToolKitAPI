using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>Generates a symmetric AES key for use with the <c>aes-gcm</c> encryption method.</summary>
    public sealed class AesKeyGenerator : KeyGeneratorBase
    {
        /// <inheritdoc />
        public override string Name => "aes";

        /// <inheritdoc />
        public override IReadOnlyCollection<string> Aliases => new[] { "aes-gcm", "aesgcm" };

        /// <inheritdoc />
        public override string Description => "Random AES key for AES-GCM authenticated encryption.";

        /// <inheritdoc />
        public override IReadOnlyCollection<int> SupportedKeySizes => new[] { 128, 192, 256 };

        /// <inheritdoc />
        public override int DefaultKeySize => 256;

        /// <inheritdoc />
        protected override GeneratedKey GenerateCore(int keySizeBits) => new()
        {
            Algorithm = "AES-GCM",
            KeySizeBits = keySizeBits,
            Key = Base64Text.Encode(RandomNumberGenerator.GetBytes(keySizeBits / 8)),
            KeyFormat = "Base64 encoded raw AES key."
        };
    }
}
