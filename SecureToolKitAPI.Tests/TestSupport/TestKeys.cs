using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.KeyGeneration;

namespace SecureToolKitAPI.Tests.TestSupport
{
    /// <summary>
    /// Generates throwaway key material for tests using the same generators the API uses.
    /// </summary>
    /// <remarks>
    /// Every value is generated fresh in-process, so no production secret is ever used and nothing
    /// needs to be stored in source. Tests must not print these values.
    /// </remarks>
    public static class TestKeys
    {
        /// <summary>Generates an AES key.</summary>
        public static string Aes(int keySize = 256) =>
            Required(new AesKeyGenerator().Generate(keySize).Key);

        /// <summary>Generates an HMAC secret.</summary>
        public static string HmacSecret(int keySize = 256) =>
            Required(new HmacKeyGenerator().Generate(keySize).Key);

        /// <summary>Generates a general purpose random secret.</summary>
        public static string RandomSecret(int keySize = 256) =>
            Required(new RandomSecretGenerator().Generate(keySize).Key);

        /// <summary>Generates an RSA key pair.</summary>
        public static GeneratedKey Rsa(int keySize = 2048) => new RsaKeyGenerator().Generate(keySize);

        /// <summary>Generates an ECDH key pair.</summary>
        public static GeneratedKey Ecdh(int keySize = 256) => new EcdhKeyGenerator().Generate(keySize);

        /// <summary>Generates an ECDSA key pair.</summary>
        public static GeneratedKey Ecdsa(int keySize = 256) => new EcdsaKeyGenerator().Generate(keySize);

        /// <summary>Returns the public key of a generated pair.</summary>
        public static string PublicKey(this GeneratedKey generated) => Required(generated.PublicKey);

        /// <summary>Returns the private key of a generated pair.</summary>
        public static string PrivateKey(this GeneratedKey generated) => Required(generated.PrivateKey);

        private static string Required(string? value) =>
            value ?? throw new InvalidOperationException("The generator did not return the expected key material.");
    }
}
