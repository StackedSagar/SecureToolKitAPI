using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>
    /// Generates an ECDSA key pair for the <c>ecc-dss</c> signature method.
    /// </summary>
    /// <remarks>
    /// ECDSA provides integrity and origin authentication, not confidentiality, so these keys are
    /// used by the signature endpoints rather than the encryption endpoints.
    /// </remarks>
    public sealed class EcdsaKeyGenerator : KeyGeneratorBase
    {
        /// <inheritdoc />
        public override string Name => "ecc-dss";

        /// <inheritdoc />
        public override IReadOnlyCollection<string> Aliases => new[] { "eccdss", "ecdsa" };

        /// <inheritdoc />
        public override string Description => "ECDSA key pair for digital signatures.";

        /// <inheritdoc />
        public override IReadOnlyCollection<int> SupportedKeySizes => new[] { 256, 384, 521 };

        /// <inheritdoc />
        public override int DefaultKeySize => 256;

        /// <inheritdoc />
        protected override GeneratedKey GenerateCore(int keySizeBits)
        {
            using var ecdsa = ECDsa.Create(EcCurves.FromKeySize(keySizeBits));

            return new GeneratedKey
            {
                Algorithm = "ECC-DSA",
                KeySizeBits = keySizeBits,
                PublicKey = Base64Text.Encode(ecdsa.ExportSubjectPublicKeyInfo()),
                PrivateKey = Base64Text.Encode(ecdsa.ExportPkcs8PrivateKey()),
                KeyFormat = "Base64 encoded SubjectPublicKeyInfo public key and PKCS#8 private key."
            };
        }
    }
}
