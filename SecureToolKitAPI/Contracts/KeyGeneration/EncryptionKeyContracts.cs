using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Contracts.KeyGeneration
{
    /// <summary>
    /// Options for the general-purpose encryption-key endpoint: which method to generate for, and the key
    /// size to use.
    /// </summary>
    /// <remarks>
    /// Both members are optional. Omit the body entirely for a 256-bit AES key, which is what most callers
    /// mean by "an encryption key".
    /// </remarks>
    public sealed record EncryptionKeyRequest
    {
        /// <summary>
        /// Method name or alias, for example <c>aes</c>, <c>rsa</c>, <c>ecc-hillman</c>, <c>hmac</c> or
        /// <c>random</c>. Matched case-insensitively. The full list, with the sizes each method accepts, is
        /// returned by <c>GET /api/keygen/methods</c>. Defaults to <c>aes</c>.
        /// </summary>
        public string? Method { get; init; }

        /// <summary>Requested key size in bits. Omit to use the default for the method.</summary>
        public int? KeySize { get; init; }
    }

    /// <summary>Options for a generated salt.</summary>
    public sealed record SaltRequest
    {
        /// <summary>Bytes of randomness. Between 8 and 64; defaults to 16, which is 128 bits.</summary>
        public int? Bytes { get; init; }

        /// <summary>
        /// How the salt is written down: <c>base64</c>, <c>base64url</c>, <c>hex</c> or <c>hexUpper</c>.
        /// Defaults to <c>base64</c>. <c>base62</c> is rejected, because it samples characters rather than
        /// encoding bytes and so cannot be decoded back to the salt that was generated.
        /// </summary>
        public string? Encoding { get; init; }
    }

    /// <summary>A generated salt.</summary>
    /// <remarks>
    /// A salt is not secret material, which makes this the one generation response in this API that is
    /// safe to store next to the data it belongs to — and it has to be, or the hash cannot be verified.
    /// </remarks>
    public sealed record SaltResponse
    {
        /// <summary>The salt, in the requested encoding.</summary>
        public required string Value { get; init; }

        /// <summary>Number of random bytes behind <see cref="Value"/>.</summary>
        public required int Bytes { get; init; }

        /// <summary>How <see cref="Value"/> is encoded, so a caller knows what to decode.</summary>
        public required string Format { get; init; }

        /// <summary>Advisories about how a salt must be used.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// Maps generated key material to the response shapes the key-generation endpoints return, so the
    /// mapping is defined once rather than repeated in every controller that exposes a generator.
    /// </summary>
    internal static class GeneratedKeyMapper
    {
        /// <summary>Maps generated key material to the method-agnostic response.</summary>
        /// <param name="method">Canonical method name to report back to the caller.</param>
        /// <param name="generated">The generated key material.</param>
        internal static GeneratedKeyResponse ToGeneratedKey(string method, GeneratedKey generated) => new()
        {
            Method = method,
            Algorithm = generated.Algorithm,
            KeySize = generated.KeySizeBits,
            KeyFormat = generated.KeyFormat,
            Key = generated.Key,
            PublicKey = generated.PublicKey,
            PrivateKey = generated.PrivateKey,
            Warnings = generated.Warnings
        };

        /// <summary>Maps generated key material to the symmetric response.</summary>
        /// <param name="generated">The generated key material.</param>
        /// <exception cref="InvalidOperationException">
        /// The generator did not produce a symmetric key, which means an endpoint is wired to a generator
        /// of the wrong shape.
        /// </exception>
        internal static SymmetricKeyResponse ToSymmetric(GeneratedKey generated) => new()
        {
            Algorithm = generated.Algorithm,
            Key = generated.Key ?? throw MissingMaterial(generated.Algorithm),
            KeySize = generated.KeySizeBits,
            KeyFormat = generated.KeyFormat,
            Warnings = generated.Warnings
        };

        /// <summary>Maps generated key material to the key-pair response.</summary>
        /// <param name="generated">The generated key material.</param>
        /// <exception cref="InvalidOperationException">
        /// The generator did not produce a key pair, which means an endpoint is wired to a generator of the
        /// wrong shape.
        /// </exception>
        internal static KeyPairResponse ToKeyPair(GeneratedKey generated) => new()
        {
            Algorithm = generated.Algorithm,
            PublicKey = generated.PublicKey ?? throw MissingMaterial(generated.Algorithm),
            PrivateKey = generated.PrivateKey ?? throw MissingMaterial(generated.Algorithm),
            KeySize = generated.KeySizeBits,
            KeyFormat = generated.KeyFormat,
            Warnings = generated.Warnings
        };

        /// <summary>Maps a generated salt to its response.</summary>
        /// <param name="generated">The generated salt.</param>
        internal static SaltResponse ToSalt(GeneratedSalt generated) => new()
        {
            Value = generated.Value,
            Bytes = generated.Bytes,
            Format = generated.Format,
            Warnings = generated.Warnings
        };

        // Reachable only if an endpoint is wired to a generator of the wrong shape, which is a defect
        // rather than a caller error. The message deliberately carries no key material.
        private static InvalidOperationException MissingMaterial(string algorithm) =>
            new($"The generator for '{algorithm}' did not return the key material this endpoint expects.");
    }
}
