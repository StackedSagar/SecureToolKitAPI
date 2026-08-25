using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.DeveloperSecrets;
using SecureToolKitAPI.Cryptography.Encryption;
using SecureToolKitAPI.Cryptography.FrameworkKeys;
using SecureToolKitAPI.Cryptography.Hashing;
using SecureToolKitAPI.Cryptography.Identity;
using SecureToolKitAPI.Cryptography.KeyGeneration;
using SecureToolKitAPI.Cryptography.Network;
using SecureToolKitAPI.Cryptography.PasswordGeneration;
using SecureToolKitAPI.Cryptography.Recovery;
using SecureToolKitAPI.Cryptography.Salts;
using SecureToolKitAPI.Cryptography.Signing;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SecureToolKitAPI.Application
{
    /// <summary>
    /// Registration for the cryptography and application layers, called from the composition root in
    /// <c>Program.cs</c>. Adding a method means adding one descriptor here; controllers and API
    /// contracts stay unchanged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Registration is split per layer so each method has a single reason to change: the cryptography
    /// layer changes when an algorithm is added, the application layer changes when orchestration is
    /// added. <c>Program.cs</c> composes them in order and owns the lifetime decisions.
    /// </para>
    /// <para>
    /// Every registration uses the <c>TryAdd</c> family, so composing a layer twice cannot produce a
    /// duplicate method identifier — which the registry would otherwise reject at startup.
    /// </para>
    /// </remarks>
    public static class CryptographyServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the whole cryptography stack: every algorithm, the registries that resolve them
        /// and the application services that orchestrate them.
        /// </summary>
        /// <param name="services">The service collection to add to.</param>
        /// <returns>The same service collection, for chaining.</returns>
        /// <remarks>
        /// A convenience aggregate over <see cref="AddCryptographyMethods"/> and
        /// <see cref="AddCryptographyApplicationServices"/>, kept so existing callers and tests can
        /// register the complete stack in one line.
        /// </remarks>
        public static IServiceCollection AddCryptography(this IServiceCollection services) =>
            services
                .AddCryptographyMethods()
                .AddCryptographyApplicationServices();

        /// <summary>
        /// Registers the cryptography layer: each key generator, encryption method and signature
        /// method, plus the registry that resolves one method family from a caller-supplied identifier.
        /// </summary>
        /// <param name="services">The service collection to add to.</param>
        /// <returns>The same service collection, for chaining.</returns>
        /// <remarks>
        /// These implementations hold no per-request state and only call thread-safe .NET
        /// cryptographic APIs, so they are singletons: the registries are indexed once at startup
        /// rather than rebuilt for every request, and a duplicate identifier fails immediately.
        /// </remarks>
        public static IServiceCollection AddCryptographyMethods(this IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services);

            // Key generation. One descriptor per generator; the registry discovers them all.
            services.TryAddEnumerable(
            [
                ServiceDescriptor.Singleton<IKeyGenerator, AesKeyGenerator>(),
                ServiceDescriptor.Singleton<IKeyGenerator, RsaKeyGenerator>(),
                ServiceDescriptor.Singleton<IKeyGenerator, EcdhKeyGenerator>(),
                ServiceDescriptor.Singleton<IKeyGenerator, EcdsaKeyGenerator>(),
                ServiceDescriptor.Singleton<IKeyGenerator, HmacKeyGenerator>(),
                ServiceDescriptor.Singleton<IKeyGenerator, RandomSecretGenerator>()
            ]);

            // Encryption and the corresponding decryption, paired per method.
            services.TryAddEnumerable(
            [
                ServiceDescriptor.Singleton<IEncryptionMethod, AesGcmEncryptionMethod>(),
                ServiceDescriptor.Singleton<IEncryptionMethod, RsaOaepEncryptionMethod>(),
                ServiceDescriptor.Singleton<IEncryptionMethod, EcdhAesGcmEncryptionMethod>()
            ]);

            // Signing and verification.
            services.TryAddEnumerable(
            [
                ServiceDescriptor.Singleton<ISignatureMethod, EcdsaSignatureMethod>(),
                ServiceDescriptor.Singleton<ISignatureMethod, HmacSha256SignatureMethod>()
            ]);

            services.TryAddSingleton<CryptographicMethodRegistry<IKeyGenerator>>();
            services.TryAddSingleton<CryptographicMethodRegistry<IEncryptionMethod>>();
            services.TryAddSingleton<CryptographicMethodRegistry<ISignatureMethod>>();

            // Password generation. Not a method family — there is one generator with several shapes of
            // output — so it is registered directly rather than through a registry.
            services.TryAddSingleton<IPasswordGenerator, PasswordGenerator>();

            // Developer secrets, for the same reason: one stateless generator covering several shapes of
            // output rather than a family of interchangeable algorithms.
            services.TryAddSingleton<IDeveloperSecretGenerator, DeveloperSecretGenerator>();

            // Salts. Not a method family either: there is no algorithm to select and no key size to
            // validate, only a size and an encoding.
            services.TryAddSingleton<ISaltGenerator, SaltGenerator>();

            // Account recovery: backup codes and recovery keys. Same reasoning again — one stateless
            // generator, no algorithm to select.
            services.TryAddSingleton<IRecoveryGenerator, RecoveryGenerator>();

            // Identity and second-factor values: UUIDs, TOTP secrets, enrollments and Base32. Same
            // reasoning once more — one stateless generator, and no algorithm registry to select from,
            // because the TOTP hash function is a parameter of the enrollment rather than a method.
            services.TryAddSingleton<IIdentityGenerator, IdentityGenerator>();

            // Framework secrets: the Django, Flask, Laravel and WordPress values. Registered directly for
            // the same reason as the others — the framework is named by the route rather than resolved from
            // a caller-supplied identifier, so there is no family to look up.
            services.TryAddSingleton<IFrameworkKeyGenerator, FrameworkKeyGenerator>();

            // SSH key pairs. Registered directly as well: the algorithm is chosen per request from a small
            // fixed set rather than resolved from a registry of interchangeable methods, and the generator
            // itself only calls RSA.Create and ECDsa.Create.
            services.TryAddSingleton<INetworkKeyGenerator, NetworkKeyGenerator>();

            // Password analysis. Pure computation over the caller's input with no state of its own, so a
            // shared instance is correct and nothing about one request can reach another.
            services.TryAddSingleton<IPasswordAnalyzer, PasswordAnalyzer>();

            // Hashing. Not a method family — one stateless generator over a small fixed set of hash functions,
            // and the function is a parameter of the request rather than a service to resolve. It produces no
            // secret and takes no key, so it needs neither a registry nor request scope; a shared instance
            // calling the .NET one-shot HashData APIs is correct.
            services.TryAddSingleton<IHashGenerator, HashGenerator>();

            return services;
        }

        /// <summary>
        /// Registers the application layer: the orchestration services that controllers depend on
        /// through their interfaces.
        /// </summary>
        /// <param name="services">The service collection to add to.</param>
        /// <returns>The same service collection, for chaining.</returns>
        /// <remarks>
        /// These are scoped, so each HTTP request orchestrates through its own instance and any
        /// request-scoped collaborator added later can be injected without turning a singleton into a
        /// captive dependency. Depending on the singleton registries from a scoped service is safe;
        /// the reverse would not be, and <c>Program.cs</c> enables scope validation to prove it.
        /// </remarks>
        public static IServiceCollection AddCryptographyApplicationServices(this IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services);

            services.TryAddScoped<IKeyGenerationService, KeyGenerationService>();
            services.TryAddScoped<IEncryptionService, EncryptionService>();
            services.TryAddScoped<IDecryptionService, DecryptionService>();
            services.TryAddScoped<ISignatureService, SignatureService>();

            return services;
        }
    }
}
