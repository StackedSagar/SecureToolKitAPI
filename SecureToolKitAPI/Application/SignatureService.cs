using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>Outcome of a signing request.</summary>
    /// <param name="Method">The resolved signature method.</param>
    /// <param name="Signature">Base64 signature.</param>
    public sealed record SigningOutcome(ISignatureMethod Method, string Signature);

    /// <summary>Outcome of a verification request.</summary>
    /// <param name="Method">The resolved signature method.</param>
    /// <param name="IsValid">Whether the signature matched.</param>
    public sealed record VerificationOutcome(ISignatureMethod Method, bool IsValid);

    /// <summary>
    /// Orchestrates message signing and verification. Signing provides integrity and origin only,
    /// so it is kept separate from the encryption endpoints.
    /// </summary>
    /// <remarks>
    /// Registered per request (scoped); the signature methods it resolves are shared singletons.
    /// </remarks>
    public sealed class SignatureService(CryptographicMethodRegistry<ISignatureMethod> registry)
        : ISignatureService
    {
        /// <inheritdoc />
        public IReadOnlyList<ISignatureMethod> Methods => registry.Methods;

        /// <inheritdoc />
        public SigningOutcome Sign(string? method, string key, string message)
        {
            var resolved = registry.Resolve(method);

            return new SigningOutcome(resolved, resolved.Sign(key, message));
        }

        /// <inheritdoc />
        public VerificationOutcome Verify(string? method, string key, string message, string signature)
        {
            var resolved = registry.Resolve(method);

            return new VerificationOutcome(resolved, resolved.Verify(key, message, signature));
        }
    }
}
