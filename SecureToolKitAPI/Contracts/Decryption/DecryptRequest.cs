using System.ComponentModel.DataAnnotations;

namespace SecureToolKitAPI.Contracts.Decryption
{
    /// <summary>Request to decrypt an envelope produced by the matching encryption method.</summary>
    public sealed record DecryptRequest
    {
        /// <summary>
        /// Base64 key material compatible with the selected method: the same symmetric key for
        /// <c>aes-gcm</c>, or the recipient private key for <c>rsa-oaep</c> and <c>ecc-hillman</c>.
        /// </summary>
        [Required(AllowEmptyStrings = false, ErrorMessage = "A key is required.")]
        public string Key { get; init; } = string.Empty;

        /// <summary>Base64 envelope exactly as returned by <c>POST /api/encrypt/{method}</c>.</summary>
        [Required(AllowEmptyStrings = false, ErrorMessage = "An encrypted message is required.")]
        public string EncryptedMessage { get; init; } = string.Empty;
    }
}
