using System.ComponentModel.DataAnnotations;

namespace SecureToolKitAPI.Contracts.Signing
{
    /// <summary>Request to sign a message.</summary>
    public sealed record SignRequest
    {
        /// <summary>
        /// Base64 signing key: the EC private key for <c>ecc-dss</c>, or the shared secret for
        /// <c>hmac-sha256</c>.
        /// </summary>
        [Required(AllowEmptyStrings = false, ErrorMessage = "A key is required.")]
        public string Key { get; init; } = string.Empty;

        /// <summary>Message to sign. An empty message is accepted.</summary>
        [Required(AllowEmptyStrings = true, ErrorMessage = "A message is required.")]
        public string Message { get; init; } = string.Empty;
    }

    /// <summary>Result of a signing request.</summary>
    public sealed record SignResponse
    {
        /// <summary>Canonical name of the signature method used.</summary>
        public required string Method { get; init; }

        /// <summary>Base64 signature or authentication code.</summary>
        public required string Signature { get; init; }

        /// <summary>Encoding of the returned signature.</summary>
        public required string SignatureFormat { get; init; }
    }

    /// <summary>Request to verify a signature.</summary>
    public sealed record VerifyRequest
    {
        /// <summary>
        /// Base64 verification key: the EC public key for <c>ecc-dss</c>, or the same shared secret
        /// for <c>hmac-sha256</c>.
        /// </summary>
        [Required(AllowEmptyStrings = false, ErrorMessage = "A key is required.")]
        public string Key { get; init; } = string.Empty;

        /// <summary>Message that was signed. An empty message is accepted.</summary>
        [Required(AllowEmptyStrings = true, ErrorMessage = "A message is required.")]
        public string Message { get; init; } = string.Empty;

        /// <summary>Base64 signature to check.</summary>
        [Required(AllowEmptyStrings = false, ErrorMessage = "A signature is required.")]
        public string Signature { get; init; } = string.Empty;
    }

    /// <summary>Result of a verification request.</summary>
    public sealed record VerifyResponse
    {
        /// <summary>Canonical name of the signature method used.</summary>
        public required string Method { get; init; }

        /// <summary>
        /// <c>true</c> when the signature is valid for the supplied message and key.
        /// A <c>false</c> value is a normal, successful response - not an error.
        /// </summary>
        public required bool IsValid { get; init; }
    }
}
