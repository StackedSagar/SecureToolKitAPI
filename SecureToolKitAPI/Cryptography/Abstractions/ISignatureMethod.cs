namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Produces and verifies message signatures. Signing proves integrity and origin;
    /// it does not provide confidentiality and is deliberately kept separate from encryption.
    /// </summary>
    public interface ISignatureMethod : ICryptographicMethod
    {
        /// <summary>Description of the key material used for signing.</summary>
        string SigningKeyFormat { get; }

        /// <summary>Description of the key material used for verification.</summary>
        string VerificationKeyFormat { get; }

        /// <summary>Encoding of the produced signature.</summary>
        string SignatureFormat { get; }

        /// <summary>
        /// Signs <paramref name="message"/>.
        /// </summary>
        /// <param name="key">Base64 signing key.</param>
        /// <param name="message">UTF-8 message to sign.</param>
        /// <returns>Base64 signature.</returns>
        /// <exception cref="CryptographicRequestException">The key or message is not valid for this method.</exception>
        string Sign(string key, string message);

        /// <summary>
        /// Verifies a signature over <paramref name="message"/>.
        /// </summary>
        /// <param name="key">Base64 verification key.</param>
        /// <param name="message">UTF-8 message that was signed.</param>
        /// <param name="signature">Base64 signature to check.</param>
        /// <returns><c>true</c> when the signature is valid, otherwise <c>false</c>.</returns>
        /// <exception cref="CryptographicRequestException">The key or signature encoding is not valid for this method.</exception>
        bool Verify(string key, string message, string signature);
    }
}
