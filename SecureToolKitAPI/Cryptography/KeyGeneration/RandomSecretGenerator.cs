using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>
    /// Generates general purpose random secret material that is not bound to a specific algorithm.
    /// </summary>
    /// <remarks>
    /// Useful for API keys, salts and similar values. It is not accepted by the encryption endpoints,
    /// which require a key generated for the selected algorithm.
    /// </remarks>
    public sealed class RandomSecretGenerator : KeyGeneratorBase
    {
        /// <inheritdoc />
        public override string Name => "random";

        /// <inheritdoc />
        public override IReadOnlyCollection<string> Aliases => new[] { "random-secret", "secret" };

        /// <inheritdoc />
        public override string Description => "Cryptographically secure random secret of the requested size.";

        /// <inheritdoc />
        public override IReadOnlyCollection<int> SupportedKeySizes => new[] { 128, 192, 256, 384, 512, 1024 };

        /// <inheritdoc />
        public override int DefaultKeySize => 256;

        /// <inheritdoc />
        protected override GeneratedKey GenerateCore(int keySizeBits) => new()
        {
            Algorithm = "Random-Secret",
            KeySizeBits = keySizeBits,
            Key = Base64Text.Encode(RandomNumberGenerator.GetBytes(keySizeBits / 8)),
            KeyFormat = "Base64 encoded random bytes."
        };
    }
}
