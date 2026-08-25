using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>Generates an RSA key pair for use with the <c>rsa-oaep</c> encryption method.</summary>
    public sealed class RsaKeyGenerator : KeyGeneratorBase
    {
        /// <inheritdoc />
        public override string Name => "rsa";

        /// <inheritdoc />
        public override IReadOnlyCollection<string> Aliases => new[] { "rsa-oaep", "rsaoaep" };

        /// <inheritdoc />
        public override string Description => "RSA key pair for RSA-OAEP (SHA-256) encryption.";

        /// <inheritdoc />
        public override IReadOnlyCollection<int> SupportedKeySizes => new[] { 512, 1024, 2048, 3072, 4096 };

        /// <inheritdoc />
        public override int DefaultKeySize => 2048;

        /// <inheritdoc />
        protected override GeneratedKey GenerateCore(int keySizeBits)
        {
            using var rsa = RSA.Create(keySizeBits);

            var warnings = keySizeBits < KeyImport.MinimumRsaKeySizeBits
                ? new[]
                {
                    $"RSA-{keySizeBits} is retained for backward compatibility only, is not considered secure, " +
                    $"and is rejected by the encryption endpoints. Use {KeyImport.MinimumRsaKeySizeBits} bits or more."
                }
                : Array.Empty<string>();

            return new GeneratedKey
            {
                Algorithm = "RSA-OAEP",
                KeySizeBits = keySizeBits,
                PublicKey = Base64Text.Encode(rsa.ExportRSAPublicKey()),
                PrivateKey = Base64Text.Encode(rsa.ExportRSAPrivateKey()),
                KeyFormat = "Base64 encoded PKCS#1 RSAPublicKey and RSAPrivateKey.",
                Warnings = warnings
            };
        }
    }
}
