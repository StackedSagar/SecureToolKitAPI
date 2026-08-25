using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application.Abstractions
{
    /// <summary>
    /// Application service that selects a key generator and asks it for key material.
    /// </summary>
    /// <remarks>
    /// Controllers depend on this abstraction rather than on a concrete service, so the orchestration
    /// can change, be decorated or be substituted in tests without touching the HTTP layer.
    /// </remarks>
    public interface IKeyGenerationService
    {
        /// <summary>All supported key-generation methods, ordered by canonical name.</summary>
        IReadOnlyList<IKeyGenerator> Methods { get; }

        /// <summary>
        /// Generates key material using the requested method.
        /// </summary>
        /// <param name="method">Canonical name or alias of the generator.</param>
        /// <param name="keySizeBits">Requested key size in bits, or <c>null</c> for the method default.</param>
        /// <exception cref="CryptographicRequestException">
        /// The method is not supported, or the key size is not valid for it.
        /// </exception>
        GeneratedKey Generate(string? method, int? keySizeBits);
    }
}
