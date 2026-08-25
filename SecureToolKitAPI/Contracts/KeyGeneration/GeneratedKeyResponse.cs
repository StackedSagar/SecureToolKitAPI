using System.Text.Json.Serialization;

namespace SecureToolKitAPI.Contracts.KeyGeneration
{
    /// <summary>
    /// Generated key material returned by the method-agnostic key-generation endpoint. Symmetric
    /// methods populate <see cref="Key"/>; asymmetric methods populate <see cref="PublicKey"/> and
    /// <see cref="PrivateKey"/>. Members that do not apply are omitted from the response.
    /// </summary>
    /// <remarks>This response contains secret material. Treat it as sensitive and do not log it.</remarks>
    public sealed record GeneratedKeyResponse
    {
        /// <summary>Canonical name of the method that generated the key.</summary>
        public required string Method { get; init; }

        /// <summary>Algorithm the key was generated for, for example <c>AES-GCM</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Key size in bits, or curve strength for elliptic-curve keys.</summary>
        public required int KeySize { get; init; }

        /// <summary>Description of the returned key encoding.</summary>
        public required string KeyFormat { get; init; }

        /// <summary>Base64 symmetric key or secret, for symmetric methods.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Key { get; init; }

        /// <summary>Base64 public key, for asymmetric methods.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? PublicKey { get; init; }

        /// <summary>Base64 private key, for asymmetric methods.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? PrivateKey { get; init; }

        /// <summary>Non-fatal advisories about the generated key.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
