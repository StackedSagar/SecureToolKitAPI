using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Encryption;
using Xunit;

namespace SecureToolKitAPI.Tests.TestSupport
{
    /// <summary>
    /// A method under test together with freshly generated keys that are valid for it.
    /// </summary>
    /// <param name="Method">The encryption method.</param>
    /// <param name="EncryptionKey">Key accepted by <see cref="IEncryptor.Encrypt"/>.</param>
    /// <param name="DecryptionKey">Key accepted by <see cref="IDecryptor.Decrypt"/>.</param>
    /// <param name="WrongDecryptionKey">A valid key of the same kind that must not decrypt the envelope.</param>
    /// <param name="LargestMessage">The largest message this scenario should attempt.</param>
    public sealed record EncryptionScenario(
        IEncryptionMethod Method,
        string EncryptionKey,
        string DecryptionKey,
        string WrongDecryptionKey,
        string LargestMessage);

    /// <summary>Builds the scenarios shared by the cross-method encryption tests.</summary>
    public static class EncryptionScenarios
    {
        /// <summary>Canonical name of the symmetric AES-GCM method.</summary>
        public const string AesGcm = "aes-gcm";

        /// <summary>Canonical name of the RSA-OAEP method.</summary>
        public const string RsaOaep = "rsa-oaep";

        /// <summary>Canonical name of the hybrid ECDH + AES-GCM method.</summary>
        public const string EcdhAesGcm = "ecc-hillman";

        /// <summary>Every method that supports encryption and decryption.</summary>
        public static TheoryData<string> AllMethods => new() { AesGcm, RsaOaep, EcdhAesGcm };

        /// <summary>Methods whose envelope carries an AES-GCM authentication tag.</summary>
        public static TheoryData<string> AuthenticatedMethods => new() { AesGcm, EcdhAesGcm };

        /// <summary>Every method paired with each message it must round trip.</summary>
        public static TheoryData<string, string> AllMethodsAndMessages
        {
            get
            {
                var data = new TheoryData<string, string>();

                foreach (var method in new[] { AesGcm, RsaOaep, EcdhAesGcm })
                {
                    foreach (var message in TestMessages.UniversallySupported())
                    {
                        data.Add(method, message);
                    }
                }

                return data;
            }
        }

        /// <summary>Creates a scenario with freshly generated keys.</summary>
        public static EncryptionScenario Create(string methodName)
        {
            switch (methodName)
            {
                case AesGcm:
                    var key = TestKeys.Aes();
                    return new EncryptionScenario(
                        new AesGcmEncryptionMethod(), key, key, TestKeys.Aes(), TestMessages.Long);

                case RsaOaep:
                    var rsa = TestKeys.Rsa();
                    return new EncryptionScenario(
                        new RsaOaepEncryptionMethod(),
                        rsa.PublicKey(),
                        rsa.PrivateKey(),
                        TestKeys.Rsa().PrivateKey(),
                        TestMessages.RsaMaximumFor2048);

                case EcdhAesGcm:
                    var ecdh = TestKeys.Ecdh();
                    return new EncryptionScenario(
                        new EcdhAesGcmEncryptionMethod(),
                        ecdh.PublicKey(),
                        ecdh.PrivateKey(),
                        TestKeys.Ecdh().PrivateKey(),
                        TestMessages.Long);

                default:
                    throw new ArgumentOutOfRangeException(nameof(methodName), methodName, "Unknown encryption method.");
            }
        }
    }
}
