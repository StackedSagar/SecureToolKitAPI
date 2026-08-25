using SecureToolKitAPI.Application;
using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Contracts.Decryption;
using SecureToolKitAPI.Contracts.Methods;
using Microsoft.AspNetCore.Mvc;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Decrypts envelopes produced by <see cref="EncryptController"/>. The cryptography lives in the
    /// decryption methods; this controller only validates the request, selects the method and maps the
    /// result.
    /// </summary>
    /// <remarks>
    /// Keys and ciphertext are accepted in the request body, never in the URL, so they do not appear in
    /// server or proxy access logs.
    /// </remarks>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class DecryptController(IDecryptionService decryption) : ControllerBase
    {
        /// <summary>
        /// Lists the supported decryption methods and the key material each expects.
        /// </summary>
        /// <returns>Returns one entry per supported method.</returns>
        [HttpGet("methods")]
        [ProducesResponseType<IEnumerable<EncryptionMethodResponse>>(StatusCodes.Status200OK)]
        public IActionResult GetMethods() =>
            Ok(decryption.Methods.Select(method => new EncryptionMethodResponse
            {
                Name = method.Name,
                Aliases = method.Aliases,
                Description = method.Description,
                KeyFormat = method.KeyFormat,
                EnvelopeLayout = method.EnvelopeLayout
            }));

        /// <summary>
        /// Decrypts an envelope using the method that produced it and a compatible generated key.
        /// </summary>
        /// <param name="method">
        /// Method name or alias: <c>aes-gcm</c> (the same symmetric key), <c>rsa-oaep</c> (recipient
        /// private key) or <c>ecc-hillman</c> (recipient private key). Matched case-insensitively.
        /// </param>
        /// <param name="request">The key and the envelope to decrypt.</param>
        /// <returns>Returns the original message when the key and envelope are valid.</returns>
        /// <remarks>
        /// A wrong key, a truncated envelope, an envelope from a different method, or any alteration of
        /// the ciphertext or authentication tag is reported as a bad request without revealing why.
        /// </remarks>
        [HttpPost("{method}")]
        [Consumes("application/json")]
        [ProducesResponseType<DecryptResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult Decrypt(string method, [FromBody] DecryptRequest request)
        {
            var outcome = decryption.Decrypt(method, request.Key, request.EncryptedMessage);

            return Ok(new DecryptResponse
            {
                Method = outcome.Method.Name,
                Message = outcome.Message
            });
        }
    }
}
