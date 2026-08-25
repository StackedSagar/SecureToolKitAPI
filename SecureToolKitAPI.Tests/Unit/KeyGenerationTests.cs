using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.KeyGeneration;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Verifies that every key generator produces key material of the requested size, in the declared
    /// format, and rejects sizes it does not support.
    /// </summary>
    /// <remarks>
    /// Assertions never compare or display key material directly, so no key value can reach the test
    /// output even when a test fails.
    /// </remarks>
    public class KeyGenerationTests
    {
        /// <summary>Symmetric generators paired with each key size they accept.</summary>
        public static TheoryData<string, int> SymmetricSizes
        {
            get
            {
                var data = new TheoryData<string, int>();

                foreach (var size in new[] { 128, 192, 256 })
                {
                    data.Add("aes", size);
                }

                foreach (var size in new[] { 128, 256, 384, 512 })
                {
                    data.Add("hmac", size);
                }

                foreach (var size in new[] { 128, 192, 256, 384, 512, 1024 })
                {
                    data.Add("random", size);
                }

                return data;
            }
        }

        /// <summary>Elliptic-curve generators paired with each curve size they accept.</summary>
        public static TheoryData<string, int> EllipticCurveSizes
        {
            get
            {
                var data = new TheoryData<string, int>();

                foreach (var name in new[] { "ecc-hillman", "ecc-dss" })
                {
                    foreach (var size in new[] { 256, 384, 521 })
                    {
                        data.Add(name, size);
                    }
                }

                return data;
            }
        }

        /// <summary>Every generator paired with a size it must reject.</summary>
        public static TheoryData<string, int> UnsupportedSizes
        {
            get
            {
                var data = new TheoryData<string, int>();

                foreach (var name in new[] { "aes", "rsa", "ecc-hillman", "ecc-dss", "hmac", "random" })
                {
                    foreach (var size in new[] { 0, -256, 1, 100, 255, 999_999 })
                    {
                        data.Add(name, size);
                    }
                }

                return data;
            }
        }

        [Theory]
        [MemberData(nameof(SymmetricSizes))]
        public void Symmetric_generator_returns_a_key_of_the_requested_length(string name, int keySize)
        {
            var generated = Generator(name).Generate(keySize);

            Assert.Equal(keySize, generated.KeySizeBits);
            Assert.NotNull(generated.Key);
            Assert.Equal(keySize / 8, Convert.FromBase64String(generated.Key!).Length);
            Assert.Null(generated.PublicKey);
            Assert.Null(generated.PrivateKey);
            Assert.False(string.IsNullOrWhiteSpace(generated.KeyFormat));
            Assert.Empty(generated.Warnings);
        }

        [Theory]
        [InlineData("aes", "AES-GCM")]
        [InlineData("rsa", "RSA-OAEP")]
        [InlineData("ecc-hillman", "ECC-Hillman")]
        [InlineData("ecc-dss", "ECC-DSA")]
        [InlineData("hmac", "HMAC-SHA256")]
        [InlineData("random", "Random-Secret")]
        public void Generator_reports_its_algorithm_label(string name, string expectedAlgorithm)
        {
            // RSA is generated at its smallest supported size here purely to keep the test fast.
            var keySize = name == "rsa" ? 512 : (int?)null;

            Assert.Equal(expectedAlgorithm, Generator(name).Generate(keySize).Algorithm);
        }

        [Theory]
        [InlineData("aes", 256)]
        [InlineData("rsa", 2048)]
        [InlineData("ecc-hillman", 256)]
        [InlineData("ecc-dss", 256)]
        [InlineData("hmac", 256)]
        [InlineData("random", 256)]
        public void Generator_uses_its_default_size_when_none_is_requested(string name, int expectedDefault)
        {
            var generator = Generator(name);

            Assert.Equal(expectedDefault, generator.DefaultKeySize);
            Assert.Equal(expectedDefault, generator.Generate(null).KeySizeBits);
        }

        [Theory]
        [MemberData(nameof(UnsupportedSizes))]
        public void Generator_rejects_an_unsupported_key_size(string name, int keySize)
        {
            var exception = Assert.Throws<CryptographicRequestException>(() => Generator(name).Generate(keySize));

            Assert.Contains("Supported sizes are", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("aes")]
        [InlineData("hmac")]
        [InlineData("random")]
        [InlineData("ecc-hillman")]
        [InlineData("ecc-dss")]
        public void Generator_produces_different_material_every_time(string name)
        {
            var generator = Generator(name);
            var first = generator.Generate(null);
            var second = generator.Generate(null);

            var firstMaterial = first.Key ?? first.PrivateKey;
            var secondMaterial = second.Key ?? second.PrivateKey;

            Assert.NotNull(firstMaterial);
            Assert.False(
                string.Equals(firstMaterial, secondMaterial, StringComparison.Ordinal),
                $"'{name}' produced identical key material twice, which indicates the randomness is broken.");
        }

        [Fact]
        public void Rsa_generator_produces_different_material_every_time()
        {
            var generator = new RsaKeyGenerator();

            // 512 bits keeps generation fast; the value is only compared for inequality.
            var first = generator.Generate(512).PrivateKey;
            var second = generator.Generate(512).PrivateKey;

            Assert.False(
                string.Equals(first, second, StringComparison.Ordinal),
                "The RSA generator produced identical key material twice, which indicates the randomness is broken.");
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        public void Rsa_generator_returns_importable_pkcs1_keys_of_the_requested_size(int keySize)
        {
            var generated = new RsaKeyGenerator().Generate(keySize);

            Assert.Equal(keySize, generated.KeySizeBits);

            using var publicKey = RSA.Create();
            publicKey.ImportRSAPublicKey(Convert.FromBase64String(generated.PublicKey!), out var publicBytesRead);

            using var privateKey = RSA.Create();
            privateKey.ImportRSAPrivateKey(Convert.FromBase64String(generated.PrivateKey!), out var privateBytesRead);

            Assert.Equal(keySize, publicKey.KeySize);
            Assert.Equal(keySize, privateKey.KeySize);
            Assert.True(publicBytesRead > 0);
            Assert.True(privateBytesRead > 0);
            Assert.Null(generated.Key);
        }

        [Theory]
        [InlineData(3072)]
        [InlineData(4096)]
        public void Rsa_generator_accepts_the_larger_sizes(int keySize)
        {
            // Generating 3072 and 4096 bit keys is slow, so only the accepted-size contract is asserted.
            Assert.Contains(keySize, new RsaKeyGenerator().SupportedKeySizes);
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        public void Rsa_generator_warns_about_key_sizes_the_encryption_endpoints_reject(int keySize)
        {
            var warning = Assert.Single(new RsaKeyGenerator().Generate(keySize).Warnings);

            Assert.Contains("backward compatibility", warning, StringComparison.Ordinal);
        }

        [Fact]
        public void Rsa_generator_does_not_warn_about_secure_key_sizes()
        {
            Assert.Empty(new RsaKeyGenerator().Generate(2048).Warnings);
        }

        [Theory]
        [MemberData(nameof(EllipticCurveSizes))]
        public void Elliptic_curve_generator_returns_importable_keys_of_the_requested_curve(string name, int keySize)
        {
            var generated = Generator(name).Generate(keySize);

            Assert.Equal(keySize, generated.KeySizeBits);
            Assert.Null(generated.Key);
            Assert.NotNull(generated.PublicKey);
            Assert.NotNull(generated.PrivateKey);

            using var publicKey = ECDsa.Create();
            publicKey.ImportSubjectPublicKeyInfo(Convert.FromBase64String(generated.PublicKey!), out _);

            using var privateKey = ECDsa.Create();
            privateKey.ImportPkcs8PrivateKey(Convert.FromBase64String(generated.PrivateKey!), out _);

            Assert.Equal(keySize, publicKey.KeySize);
            Assert.Equal(keySize, privateKey.KeySize);
        }

        [Theory]
        [InlineData("aes")]
        [InlineData("rsa")]
        [InlineData("ecc-hillman")]
        [InlineData("ecc-dss")]
        [InlineData("hmac")]
        [InlineData("random")]
        public void Generator_declares_a_default_size_it_actually_supports(string name)
        {
            var generator = Generator(name);

            Assert.Contains(generator.DefaultKeySize, generator.SupportedKeySizes);
            Assert.NotEmpty(generator.SupportedKeySizes);
            Assert.False(string.IsNullOrWhiteSpace(generator.Description));
        }

        private static IKeyGenerator Generator(string name) => name switch
        {
            "aes" => new AesKeyGenerator(),
            "rsa" => new RsaKeyGenerator(),
            "ecc-hillman" => new EcdhKeyGenerator(),
            "ecc-dss" => new EcdsaKeyGenerator(),
            "hmac" => new HmacKeyGenerator(),
            "random" => new RandomSecretGenerator(),
            _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown key generator.")
        };
    }
}
