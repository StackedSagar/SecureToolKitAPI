namespace SecureToolKitAPI.Contracts.KeyGeneration
{
    /// <summary>Optional parameters for a key-generation request.</summary>
    public sealed record KeyGenerationRequest
    {
        /// <summary>
        /// Requested key size in bits. Omit to use the method default.
        /// Accepted sizes are listed by <c>GET /api/keygen/methods</c>.
        /// </summary>
        public int? KeySize { get; init; }
    }
}
