namespace SecureToolKitAPI.Contracts.Encryption
{
    /// <summary>
    /// Non-secret parameters embedded in the returned envelope, exposed so the format is explicit
    /// rather than an undocumented convention. They are not needed as separate decryption inputs.
    /// </summary>
    public sealed record EncryptionParametersResponse
    {
        /// <summary>Base64 AES-GCM nonce, when the method uses one.</summary>
        public string? Nonce { get; init; }

        /// <summary>Base64 AES-GCM authentication tag, when the method uses one.</summary>
        public string? AuthenticationTag { get; init; }

        /// <summary>Base64 single-use ephemeral public key, for ECDH based methods.</summary>
        public string? EphemeralPublicKey { get; init; }
    }

    /// <summary>Result of an encryption request.</summary>
    public sealed record EncryptResponse
    {
        /// <summary>Canonical name of the method that produced the result.</summary>
        public required string Method { get; init; }

        /// <summary>
        /// Base64 self-contained envelope. Send this value, with the compatible key, to
        /// <c>POST /api/decrypt/{method}</c> to recover the message.
        /// </summary>
        public required string EncryptedMessage { get; init; }

        /// <summary>Documented byte layout of the envelope.</summary>
        public required string EnvelopeLayout { get; init; }

        /// <summary>Non-secret parameters embedded in the envelope.</summary>
        public required EncryptionParametersResponse Parameters { get; init; }
    }
}
