using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>Outcome of an encryption request, including the canonical method name that was used.</summary>
    /// <param name="Method">The resolved encryption method.</param>
    /// <param name="Result">The envelope and its non-secret parameters.</param>
    public sealed record EncryptionOutcome(IEncryptionMethod Method, EncryptionResult Result);

    /// <summary>
    /// Orchestrates encryption: selects the requested method and delegates the cryptography to it.
    /// </summary>
    /// <remarks>
    /// Registered per request (scoped); the encryption methods it resolves are shared singletons.
    /// </remarks>
    public sealed class EncryptionService(CryptographicMethodRegistry<IEncryptionMethod> registry)
        : IEncryptionService
    {
        /// <inheritdoc />
        public IReadOnlyList<IEncryptionMethod> Methods => registry.Methods;

        /// <inheritdoc />
        public EncryptionOutcome Encrypt(string? method, string key, string message)
        {
            var resolved = registry.Resolve(method);
            IEncryptor encryptor = resolved;

            return new EncryptionOutcome(resolved, encryptor.Encrypt(key, message));
        }
    }
}
