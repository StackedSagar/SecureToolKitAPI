using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application.Abstractions
{
    /// <summary>
    /// Application service that signs messages and verifies signatures. Signing proves integrity and
    /// origin only, so it is kept separate from the encryption abstractions.
    /// </summary>
    public interface ISignatureService
    {
        /// <summary>All supported signature methods, ordered by canonical name.</summary>
        IReadOnlyList<ISignatureMethod> Methods { get; }

        /// <summary>
        /// Signs a message.
        /// </summary>
        /// <param name="method">Canonical name or alias of the signature method.</param>
        /// <param name="key">Base64 signing key.</param>
        /// <param name="message">Message to sign.</param>
        /// <exception cref="CryptographicRequestException">
        /// The method is not supported, or the key or message is not valid for it.
        /// </exception>
        SigningOutcome Sign(string? method, string key, string message);

        /// <summary>
        /// Verifies a signature. An invalid signature is a successful request with a <c>false</c>
        /// result, not an error.
        /// </summary>
        /// <param name="method">Canonical name or alias of the signature method.</param>
        /// <param name="key">Base64 verification key.</param>
        /// <param name="message">Message that was signed.</param>
        /// <param name="signature">Base64 signature to check.</param>
        /// <exception cref="CryptographicRequestException">
        /// The method is not supported, or the key or signature encoding is not valid for it.
        /// </exception>
        VerificationOutcome Verify(string? method, string key, string message, string signature);
    }
}
