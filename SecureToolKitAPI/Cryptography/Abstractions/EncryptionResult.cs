namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Non-secret cryptographic parameters produced alongside a ciphertext. These values are
    /// already embedded in the returned envelope and are surfaced only so that the format is
    /// explicit rather than relying on undocumented conventions.
    /// </summary>
    public sealed record EncryptionParameters
    {
        /// <summary>Base64 AES-GCM nonce, when the method uses one.</summary>
        public string? Nonce { get; init; }

        /// <summary>Base64 AES-GCM authentication tag, when the method uses one.</summary>
        public string? AuthenticationTag { get; init; }

        /// <summary>Base64 SubjectPublicKeyInfo of the single-use ephemeral public key, for ECDH methods.</summary>
        public string? EphemeralPublicKey { get; init; }
    }

    /// <summary>Result of an encryption operation.</summary>
    /// <param name="EncryptedMessage">
    /// Base64 self-contained envelope. This single value is everything the matching
    /// decryption method needs, alongside the compatible key.
    /// </param>
    /// <param name="Parameters">Non-secret parameters embedded in the envelope.</param>
    public sealed record EncryptionResult(string EncryptedMessage, EncryptionParameters Parameters);
}
