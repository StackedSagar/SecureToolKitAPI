namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Signals a caller-correctable problem such as an unsupported method, an invalid key size,
    /// malformed key material or an envelope that fails authentication.
    /// </summary>
    /// <remarks>
    /// The <see cref="Exception.Message"/> is returned to API consumers, so it must describe only
    /// what the caller needs to correct. It must never contain key material, plaintext, ciphertext
    /// or details of the underlying cryptographic failure.
    /// </remarks>
    public sealed class CryptographicRequestException : Exception
    {
        /// <summary>Creates the exception with a caller-safe message.</summary>
        /// <param name="message">Safe, non-sensitive description of the problem.</param>
        public CryptographicRequestException(string message)
            : base(message)
        {
        }
    }
}
