using System.ComponentModel.DataAnnotations;

namespace SecureToolKitAPI.Contracts.Encryption
{
    /// <summary>Request to encrypt a message with a previously generated key.</summary>
    public sealed record EncryptRequest
    {
        /// <summary>
        /// Base64 key material compatible with the selected method: the symmetric key for
        /// <c>aes-gcm</c>, or the recipient public key for <c>rsa-oaep</c> and <c>ecc-hillman</c>.
        /// </summary>
        [Required(AllowEmptyStrings = false, ErrorMessage = "A key is required.")]
        public string Key { get; init; } = string.Empty;

        /// <summary>Message to encrypt. An empty message is accepted.</summary>
        [Required(AllowEmptyStrings = true, ErrorMessage = "A message is required.")]
        public string Message { get; init; } = string.Empty;
    }
}
