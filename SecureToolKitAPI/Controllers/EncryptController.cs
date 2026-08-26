using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Contracts.Encryption;
using SecureToolKitAPI.Contracts.Methods;
using Microsoft.AspNetCore.Mvc;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Encrypts messages using keys produced by <see cref="KeyGenController"/>. The cryptography lives
    /// in the encryption methods; this controller only validates the request, selects the method and
    /// maps the result.
    /// </summary>
    /// <remarks>
    /// Keys and messages are accepted in the request body, never in the URL, so they do not appear in
    /// server or proxy access logs.
    /// </remarks>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class EncryptController(IEncryptionService encryption) : ControllerBase
    {
        /// <summary>
        /// Lists the supported encryption methods, the key material each expects and the envelope each produces.
        /// </summary>
        /// <returns>Returns one entry per supported method.</returns>
        [HttpGet("methods")]
        [ProducesResponseType<IEnumerable<EncryptionMethodResponse>>(StatusCodes.Status200OK)]
        public IActionResult GetMethods() =>
            Ok(encryption.Methods.Select(method => new EncryptionMethodResponse
            {
                Name = method.Name,
                Aliases = method.Aliases,
                Description = method.Description,
                KeyFormat = method.KeyFormat,
                EnvelopeLayout = method.EnvelopeLayout
            }));

        /// <summary>
        /// Encrypts a message using the selected method and a compatible generated key.
        /// </summary>
        /// <param name="method">
        /// Method name or alias: <c>aes-gcm</c> (symmetric), <c>rsa-oaep</c> (recipient public key) or
        /// <c>ecc-hillman</c> (recipient public key). Matched case-insensitively.
        /// </param>
        /// <param name="request">The key and the message to encrypt.</param>
        /// <returns>
        /// Returns a self-contained Base64 envelope. Post it unchanged to
        /// <c>POST /api/decrypt/{method}</c> with the corresponding key to recover the message.
        /// </returns>
        [HttpPost("{method}")]
        [Consumes("application/json")]
        [ProducesResponseType<EncryptResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult Encrypt(string method, [FromBody] EncryptRequest request)
        {
            var outcome = encryption.Encrypt(method, request.Key, request.Message);

            return Ok(new EncryptResponse
            {
                Method = outcome.Method.Name,
                EncryptedMessage = outcome.Result.EncryptedMessage,
                EnvelopeLayout = outcome.Method.EnvelopeLayout,
                Parameters = new EncryptionParametersResponse
                {
                    Nonce = outcome.Result.Parameters.Nonce,
                    AuthenticationTag = outcome.Result.Parameters.AuthenticationTag,
                    EphemeralPublicKey = outcome.Result.Parameters.EphemeralPublicKey
                }
            });
        }
    }
}
