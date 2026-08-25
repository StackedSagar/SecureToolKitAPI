using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>Outcome of a decryption request, including the canonical method name that was used.</summary>
    /// <param name="Method">The resolved decryption method.</param>
    /// <param name="Message">The recovered plaintext.</param>
    public sealed record DecryptionOutcome(IEncryptionMethod Method, string Message);

    /// <summary>
    /// Orchestrates decryption: selects the method that corresponds to the encryption method and
    /// delegates the cryptography to it.
    /// </summary>
    /// <remarks>
    /// Registered per request (scoped); the decryption methods it resolves are shared singletons.
    /// </remarks>
    public sealed class DecryptionService(CryptographicMethodRegistry<IEncryptionMethod> registry)
        : IDecryptionService
    {
        /// <inheritdoc />
        public IReadOnlyList<IEncryptionMethod> Methods => registry.Methods;

        /// <inheritdoc />
        public DecryptionOutcome Decrypt(string? method, string key, string encryptedMessage)
        {
            var resolved = registry.Resolve(method);
            IDecryptor decryptor = resolved;

            return new DecryptionOutcome(resolved, decryptor.Decrypt(key, encryptedMessage));
        }
    }
}
