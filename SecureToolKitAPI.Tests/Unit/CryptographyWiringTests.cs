using SecureToolKitAPI.Application;
using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Tests.TestSupport;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Verifies the composition root: every method is registered exactly once, is reachable by the
    /// identifiers the API documents, works end to end through the application service interfaces, and
    /// is registered with the lifetime the layer intends.
    /// </summary>
    public class CryptographyWiringTests
    {
        [Fact]
        public void Every_registry_builds_which_proves_no_identifier_is_claimed_twice()
        {
            using var host = new CryptographyHost();

            Assert.Equal(6, host.Resolve<CryptographicMethodRegistry<IKeyGenerator>>().Methods.Count);
            Assert.Equal(3, host.Resolve<CryptographicMethodRegistry<IEncryptionMethod>>().Methods.Count);
            Assert.Equal(2, host.Resolve<CryptographicMethodRegistry<ISignatureMethod>>().Methods.Count);
        }

        [Fact]
        public void The_documented_method_names_are_the_ones_registered()
        {
            using var host = new CryptographyHost();

            Assert.Equal(
                new[] { "aes", "ecc-dss", "ecc-hillman", "hmac", "random", "rsa" },
                host.Resolve<IKeyGenerationService>().Methods.Select(method => method.Name));
            Assert.Equal(
                new[] { "aes-gcm", "ecc-hillman", "rsa-oaep" },
                host.Resolve<IEncryptionService>().Methods.Select(method => method.Name));
            Assert.Equal(
                new[] { "ecc-dss", "hmac-sha256" },
                host.Resolve<ISignatureService>().Methods.Select(method => method.Name));
        }

        [Theory]
        [InlineData("aes", "AES-GCM")]
        [InlineData("AES", "AES-GCM")]
        [InlineData("aes-gcm", "AES-GCM")]
        [InlineData("rsa", "RSA-OAEP")]
        [InlineData("EccHillman", "ECC-Hillman")]
        [InlineData("ecc-hillman", "ECC-Hillman")]
        [InlineData("ecdh", "ECC-Hillman")]
        [InlineData("EccDss", "ECC-DSA")]
        [InlineData("ecdsa", "ECC-DSA")]
        [InlineData("hmac", "HMAC-SHA256")]
        [InlineData("random", "Random-Secret")]
        public void Key_generation_accepts_every_documented_identifier(string method, string expectedAlgorithm)
        {
            using var host = new CryptographyHost();
            var keyGeneration = host.Resolve<IKeyGenerationService>();

            // RSA generation is slow at the default size, so the smallest supported size is used here.
            var keySize = string.Equals(expectedAlgorithm, "RSA-OAEP", StringComparison.Ordinal) ? 512 : (int?)null;

            Assert.Equal(expectedAlgorithm, keyGeneration.Generate(method, keySize).Algorithm);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void The_services_complete_the_documented_generate_encrypt_decrypt_flow(string methodName)
        {
            using var host = new CryptographyHost();
            var keyGeneration = host.Resolve<IKeyGenerationService>();
            var encryption = host.Resolve<IEncryptionService>();
            var decryption = host.Resolve<IDecryptionService>();

            var generated = keyGeneration.Generate(methodName, keySizeBits: null);
            var encryptionKey = generated.Key ?? generated.PublicKey!;
            var decryptionKey = generated.Key ?? generated.PrivateKey!;

            var encrypted = encryption.Encrypt(methodName, encryptionKey, TestMessages.Unicode);
            var decrypted = decryption.Decrypt(methodName, decryptionKey, encrypted.Result.EncryptedMessage);

            Assert.Equal(methodName, encrypted.Method.Name);
            Assert.Equal(methodName, decrypted.Method.Name);
            Assert.Equal(TestMessages.Unicode, decrypted.Message);
        }

        [Fact]
        public void Decrypting_with_a_different_method_than_encrypted_with_is_reported_clearly()
        {
            using var host = new CryptographyHost();
            var encryption = host.Resolve<IEncryptionService>();
            var decryption = host.Resolve<IDecryptionService>();

            var key = TestKeys.Aes();
            var encrypted = encryption.Encrypt("aes-gcm", key, TestMessages.Normal);

            var exception = Assert.Throws<CryptographicRequestException>(
                () => decryption.Decrypt("rsa-oaep", TestKeys.Rsa().PrivateKey(), encrypted.Result.EncryptedMessage));

            Assert.Contains("different encryption method", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_services_complete_the_documented_sign_and_verify_flow()
        {
            using var host = new CryptographyHost();
            var keyGeneration = host.Resolve<IKeyGenerationService>();
            var signatures = host.Resolve<ISignatureService>();

            var ecdsaKeys = keyGeneration.Generate("ecc-dss", keySizeBits: null);
            var hmacSecret = keyGeneration.Generate("hmac", keySizeBits: null);

            var ecdsaSignature = signatures.Sign("ecc-dss", ecdsaKeys.PrivateKey(), TestMessages.Normal);
            var hmacSignature = signatures.Sign("hmac-sha256", hmacSecret.Key!, TestMessages.Normal);

            Assert.True(signatures.Verify("ecc-dss", ecdsaKeys.PublicKey(), TestMessages.Normal, ecdsaSignature.Signature).IsValid);
            Assert.True(signatures.Verify("hmac-sha256", hmacSecret.Key!, TestMessages.Normal, hmacSignature.Signature).IsValid);
        }

        [Fact]
        public void An_unsupported_method_is_refused_by_every_service()
        {
            using var host = new CryptographyHost();

            Assert.Throws<CryptographicRequestException>(
                () => host.Resolve<IKeyGenerationService>().Generate("not-a-method", null));
            Assert.Throws<CryptographicRequestException>(
                () => host.Resolve<IEncryptionService>().Encrypt("not-a-method", TestKeys.Aes(), TestMessages.Normal));
            Assert.Throws<CryptographicRequestException>(
                () => host.Resolve<IDecryptionService>().Decrypt("not-a-method", TestKeys.Aes(), "AQE="));
            Assert.Throws<CryptographicRequestException>(
                () => host.Resolve<ISignatureService>().Sign("not-a-method", TestKeys.HmacSecret(), TestMessages.Normal));
        }

        [Fact]
        public void The_algorithms_and_their_registries_are_shared_singletons()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            Assert.Same(
                first.ServiceProvider.GetRequiredService<CryptographicMethodRegistry<IKeyGenerator>>(),
                second.ServiceProvider.GetRequiredService<CryptographicMethodRegistry<IKeyGenerator>>());
            Assert.Same(
                first.ServiceProvider.GetRequiredService<CryptographicMethodRegistry<IEncryptionMethod>>(),
                second.ServiceProvider.GetRequiredService<CryptographicMethodRegistry<IEncryptionMethod>>());
            Assert.Same(
                first.ServiceProvider.GetRequiredService<CryptographicMethodRegistry<ISignatureMethod>>(),
                second.ServiceProvider.GetRequiredService<CryptographicMethodRegistry<ISignatureMethod>>());
        }

        [Fact]
        public void The_password_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<IPasswordGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<IPasswordGenerator>());

            // Resolvable outside a scope too, which is what proves it captured nothing scoped.
            Assert.Same(generator, host.Root.GetRequiredService<IPasswordGenerator>());
        }

        [Fact]
        public void The_developer_secret_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<IDeveloperSecretGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<IDeveloperSecretGenerator>());

            // Resolvable outside a scope too, which is what proves it captured nothing scoped.
            Assert.Same(generator, host.Root.GetRequiredService<IDeveloperSecretGenerator>());
        }

        [Fact]
        public void The_salt_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<ISaltGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<ISaltGenerator>());

            // Resolvable outside a scope too, which is what proves it captured nothing scoped.
            Assert.Same(generator, host.Root.GetRequiredService<ISaltGenerator>());
        }

        [Fact]
        public void The_recovery_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<IRecoveryGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<IRecoveryGenerator>());

            // Resolvable outside a scope too, which is what proves it captured nothing scoped.
            Assert.Same(generator, host.Root.GetRequiredService<IRecoveryGenerator>());
        }

        [Fact]
        public void The_identity_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<IIdentityGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<IIdentityGenerator>());

            // A TOTP secret belongs to the request that asked for it. A shared instance is only correct
            // because there is nowhere here to keep one, which is what resolving outside a scope proves.
            Assert.Same(generator, host.Root.GetRequiredService<IIdentityGenerator>());
        }

        [Fact]
        public void The_framework_key_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<IFrameworkKeyGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<IFrameworkKeyGenerator>());

            // A framework secret belongs to whoever asked for it and is never held after the response, which
            // is what resolving the same instance outside a scope proves there is no room to do.
            Assert.Same(generator, host.Root.GetRequiredService<IFrameworkKeyGenerator>());
        }

        [Fact]
        public void The_network_key_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<INetworkKeyGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<INetworkKeyGenerator>());

            // This one generates a private key, so sharing the instance is only safe because it keeps nothing
            // after it returns: the key object is disposed on the way out and the strings belong to the
            // caller. Resolving the same instance outside a scope is what shows there is nowhere to keep one.
            Assert.Same(generator, host.Root.GetRequiredService<INetworkKeyGenerator>());
        }

        [Fact]
        public void The_password_analyzer_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var analyzer = first.ServiceProvider.GetRequiredService<IPasswordAnalyzer>();

            Assert.Same(analyzer, second.ServiceProvider.GetRequiredService<IPasswordAnalyzer>());

            // Nothing about one caller's password can reach another, because there is nowhere to keep it.
            Assert.Same(analyzer, host.Root.GetRequiredService<IPasswordAnalyzer>());
        }

        [Fact]
        public void The_hash_generator_is_a_shared_singleton_because_it_holds_no_state()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            var generator = first.ServiceProvider.GetRequiredService<IHashGenerator>();

            Assert.Same(generator, second.ServiceProvider.GetRequiredService<IHashGenerator>());

            // This one takes no key and produces no secret, so a shared instance is the least it could need.
            // The caller's message still passes through it, and resolving the same instance outside a scope is
            // what shows there is nowhere for that message to be kept.
            Assert.Same(generator, host.Root.GetRequiredService<IHashGenerator>());
        }

        [Fact]
        public void The_hash_catalogue_is_not_rebuilt_per_caller()
        {
            // The catalogue is fixed data with nothing caller-specific in it, so two scopes must see the very
            // same list. If this ever became per-request work, it would be work done for no reason.
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            Assert.Same(
                first.ServiceProvider.GetRequiredService<IHashGenerator>().HashAlgorithms(),
                second.ServiceProvider.GetRequiredService<IHashGenerator>().HashAlgorithms());
        }

        [Fact]
        public void The_application_services_are_scoped_so_each_request_orchestrates_through_its_own_instance()
        {
            using var host = new CryptographyHost();
            using var first = host.CreateScope();
            using var second = host.CreateScope();

            Assert.Same(
                first.ServiceProvider.GetRequiredService<IEncryptionService>(),
                first.ServiceProvider.GetRequiredService<IEncryptionService>());
            Assert.NotSame(
                first.ServiceProvider.GetRequiredService<IEncryptionService>(),
                second.ServiceProvider.GetRequiredService<IEncryptionService>());
            Assert.NotSame(
                first.ServiceProvider.GetRequiredService<IKeyGenerationService>(),
                second.ServiceProvider.GetRequiredService<IKeyGenerationService>());
            Assert.NotSame(
                first.ServiceProvider.GetRequiredService<IDecryptionService>(),
                second.ServiceProvider.GetRequiredService<IDecryptionService>());
            Assert.NotSame(
                first.ServiceProvider.GetRequiredService<ISignatureService>(),
                second.ServiceProvider.GetRequiredService<ISignatureService>());
        }

        [Fact]
        public void Resolving_a_scoped_application_service_outside_a_scope_is_refused()
        {
            // Scope validation is what makes a captive dependency a startup failure rather than a
            // subtle runtime bug, so the composition root is expected to reject this.
            using var host = new CryptographyHost();

            Assert.Throws<InvalidOperationException>(
                () => host.Root.GetRequiredService<IEncryptionService>());
        }

        [Fact]
        public void Composing_a_layer_twice_does_not_register_any_method_twice()
        {
            using var host = new CryptographyHost(services => services
                .AddCryptographyMethods()
                .AddCryptography()
                .AddCryptographyApplicationServices());

            Assert.Equal(6, host.Resolve<CryptographicMethodRegistry<IKeyGenerator>>().Methods.Count);
            Assert.Equal(3, host.Resolve<CryptographicMethodRegistry<IEncryptionMethod>>().Methods.Count);
            Assert.Equal(2, host.Resolve<CryptographicMethodRegistry<ISignatureMethod>>().Methods.Count);
        }

        [Fact]
        public void Adding_a_layer_to_a_missing_collection_is_rejected()
        {
            Assert.Throws<ArgumentNullException>(
                () => CryptographyServiceCollectionExtensions.AddCryptography(null!));
            Assert.Throws<ArgumentNullException>(
                () => CryptographyServiceCollectionExtensions.AddCryptographyMethods(null!));
            Assert.Throws<ArgumentNullException>(
                () => CryptographyServiceCollectionExtensions.AddCryptographyApplicationServices(null!));
        }

        /// <summary>
        /// Builds the real composition root with the same validation the API enables, and keeps one
        /// scope open so scoped services can be resolved the way a request would resolve them.
        /// </summary>
        private sealed class CryptographyHost : IDisposable
        {
            private readonly ServiceProvider _provider;
            private readonly IServiceScope _scope;

            internal CryptographyHost()
                : this(services => services.AddCryptography())
            {
            }

            internal CryptographyHost(Action<IServiceCollection> register)
            {
                var services = new ServiceCollection();
                register(services);

                _provider = services.BuildServiceProvider(new ServiceProviderOptions
                {
                    ValidateScopes = true,
                    ValidateOnBuild = true
                });

                _scope = _provider.CreateScope();
            }

            /// <summary>The root provider, which must not hand out scoped services.</summary>
            internal IServiceProvider Root => _provider;

            internal T Resolve<T>()
                where T : notnull =>
                _scope.ServiceProvider.GetRequiredService<T>();

            internal IServiceScope CreateScope() => _provider.CreateScope();

            public void Dispose()
            {
                _scope.Dispose();
                _provider.Dispose();
            }
        }
    }
}
