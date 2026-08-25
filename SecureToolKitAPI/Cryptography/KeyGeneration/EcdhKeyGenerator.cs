using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>
    /// Generates an ECDH (Elliptic Curve Diffie-Hellman) key pair used for key agreement by the
    /// <c>ecc-hillman</c> hybrid encryption method.
    /// </summary>
    /// <remarks>
    /// The shared secret is derived per message from this key pair and a single-use ephemeral key,
    /// so no shared secret is returned by key generation.
    /// </remarks>
    public sealed class EcdhKeyGenerator : KeyGeneratorBase
    {
        /// <inheritdoc />
        public override string Name => "ecc-hillman";

        /// <inheritdoc />
        public override IReadOnlyCollection<string> Aliases => new[] { "ecchillman", "ecdh", "ecdh-aes-gcm" };

        /// <inheritdoc />
        public override string Description => "ECDH key pair for hybrid ECDH + AES-GCM encryption.";

        /// <inheritdoc />
        public override IReadOnlyCollection<int> SupportedKeySizes => new[] { 256, 384, 521 };

        /// <inheritdoc />
        public override int DefaultKeySize => 256;

        /// <inheritdoc />
        protected override GeneratedKey GenerateCore(int keySizeBits)
        {
            using var ecdh = ECDiffieHellman.Create(EcCurves.FromKeySize(keySizeBits));

            return new GeneratedKey
            {
                Algorithm = "ECC-Hillman",
                KeySizeBits = keySizeBits,
                PublicKey = Base64Text.Encode(ecdh.ExportSubjectPublicKeyInfo()),
                PrivateKey = Base64Text.Encode(ecdh.ExportPkcs8PrivateKey()),
                KeyFormat = "Base64 encoded SubjectPublicKeyInfo public key and PKCS#8 private key."
            };
        }
    }
}
