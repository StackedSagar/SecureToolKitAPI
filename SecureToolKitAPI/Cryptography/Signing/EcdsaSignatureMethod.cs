using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Signing
{
    /// <summary>
    /// ECDSA digital signatures over SHA-2, matching the <c>ecc-dss</c> key pair. The private key
    /// signs and the public key verifies.
    /// </summary>
    /// <remarks>
    /// The digest is chosen to match the curve: SHA-256 for P-256, SHA-384 for P-384 and SHA-512 for
    /// P-521. Signatures use IEEE P1363 fixed-field concatenation (raw r||s), which is the encoding
    /// the browser Web Crypto API expects.
    /// </remarks>
    public sealed class EcdsaSignatureMethod : ISignatureMethod
    {
        private const DSASignatureFormat SignatureEncoding = DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

        /// <inheritdoc />
        public string Name => "ecc-dss";

        /// <inheritdoc />
        public IReadOnlyCollection<string> Aliases => new[] { "eccdss", "ecdsa" };

        /// <inheritdoc />
        public string Description => "ECDSA signatures over SHA-2, matched to the curve of the supplied key.";

        /// <inheritdoc />
        public string SigningKeyFormat => "Base64 PKCS#8 EC private key, as returned by /api/keygen/EccDss.";

        /// <inheritdoc />
        public string VerificationKeyFormat => "Base64 SubjectPublicKeyInfo EC public key, as returned by /api/keygen/EccDss.";

        /// <inheritdoc />
        public string SignatureFormat => "Base64 IEEE P1363 fixed-field concatenation (raw r||s).";

        /// <inheritdoc />
        public string Sign(string key, string message)
        {
            using var ecdsa = KeyImport.ImportEcdsaPrivateKey(Base64Text.Decode(key, "key"));

            try
            {
                var signature = ecdsa.SignData(
                    Base64Text.ToUtf8(message),
                    KeyImport.HashForCurveSize(ecdsa.KeySize),
                    SignatureEncoding);

                return Base64Text.Encode(signature);
            }
            catch (CryptographicException)
            {
                throw new CryptographicRequestException(
                    "Signing failed. The supplied key could not be used for ECDSA signing.");
            }
        }

        /// <inheritdoc />
        public bool Verify(string key, string message, string signature)
        {
            using var ecdsa = KeyImport.ImportEcdsaPublicKey(Base64Text.Decode(key, "key"));

            var signatureBytes = Base64Text.Decode(signature, "signature");

            try
            {
                return ecdsa.VerifyData(
                    Base64Text.ToUtf8(message),
                    signatureBytes,
                    KeyImport.HashForCurveSize(ecdsa.KeySize),
                    SignatureEncoding);
            }
            catch (CryptographicException)
            {
                // A signature that cannot even be parsed for this curve is simply not a valid signature.
                return false;
            }
        }
    }
}
