namespace SecureToolKitAPI.Contracts.Decryption
{
    /// <summary>Result of a decryption request.</summary>
    public sealed record DecryptResponse
    {
        /// <summary>Canonical name of the method that decrypted the envelope.</summary>
        public required string Method { get; init; }

        /// <summary>The recovered plaintext message.</summary>
        public required string Message { get; init; }
    }
}
