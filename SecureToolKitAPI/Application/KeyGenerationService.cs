using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>
    /// Orchestrates key generation: selects the requested generator and lets it validate the
    /// requested key size. Nothing here inspects or logs the generated material.
    /// </summary>
    /// <remarks>
    /// Registered per request (scoped): it holds no state of its own and its only dependency is the
    /// singleton registry, so a request-scoped instance costs nothing and leaves room for future
    /// request-scoped dependencies such as an audit or usage-tracking collaborator.
    /// </remarks>
    public sealed class KeyGenerationService(CryptographicMethodRegistry<IKeyGenerator> registry)
        : IKeyGenerationService
    {
        /// <inheritdoc />
        public IReadOnlyList<IKeyGenerator> Methods => registry.Methods;

        /// <inheritdoc />
        public GeneratedKey Generate(string? method, int? keySizeBits) =>
            registry.Resolve(method).Generate(keySizeBits);
    }
}
