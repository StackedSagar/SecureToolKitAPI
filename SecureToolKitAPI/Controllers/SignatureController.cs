using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Contracts.Methods;
using SecureToolKitAPI.Contracts.Signing;
using Microsoft.AspNetCore.Mvc;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Signs and verifies messages. Signing proves integrity and origin but provides no
    /// confidentiality, so it is deliberately kept separate from the encryption endpoints.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class SignatureController(ISignatureService signatures) : ControllerBase
    {
        /// <summary>
        /// Lists the supported signature methods and the key material each expects.
        /// </summary>
        /// <returns>Returns one entry per supported method.</returns>
        [HttpGet("methods")]
        [ProducesResponseType<IEnumerable<SignatureMethodResponse>>(StatusCodes.Status200OK)]
        public IActionResult GetMethods() =>
            Ok(signatures.Methods.Select(method => new SignatureMethodResponse
            {
                Name = method.Name,
                Aliases = method.Aliases,
                Description = method.Description,
                SigningKeyFormat = method.SigningKeyFormat,
                VerificationKeyFormat = method.VerificationKeyFormat,
                SignatureFormat = method.SignatureFormat
            }));

        /// <summary>
        /// Signs a message using the selected method.
        /// </summary>
        /// <param name="method">
        /// Method name or alias: <c>ecc-dss</c> (EC private key) or <c>hmac-sha256</c> (shared secret).
        /// Matched case-insensitively.
        /// </param>
        /// <param name="request">The signing key and the message to sign.</param>
        /// <returns>Returns the Base64 signature.</returns>
        [HttpPost("{method}/sign")]
        [Consumes("application/json")]
        [ProducesResponseType<SignResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult Sign(string method, [FromBody] SignRequest request)
        {
            var outcome = signatures.Sign(method, request.Key, request.Message);

            return Ok(new SignResponse
            {
                Method = outcome.Method.Name,
                Signature = outcome.Signature,
                SignatureFormat = outcome.Method.SignatureFormat
            });
        }

        /// <summary>
        /// Verifies a signature over a message.
        /// </summary>
        /// <param name="method">
        /// Method name or alias: <c>ecc-dss</c> (EC public key) or <c>hmac-sha256</c> (the same shared
        /// secret). Matched case-insensitively.
        /// </param>
        /// <param name="request">The verification key, the message and the signature to check.</param>
        /// <returns>
        /// Returns whether the signature is valid. A signature that does not match is a successful
        /// response with <c>isValid: false</c>, not an error.
        /// </returns>
        [HttpPost("{method}/verify")]
        [Consumes("application/json")]
        [ProducesResponseType<VerifyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult Verify(string method, [FromBody] VerifyRequest request)
        {
            var outcome = signatures.Verify(method, request.Key, request.Message, request.Signature);

            return Ok(new VerifyResponse
            {
                Method = outcome.Method.Name,
                IsValid = outcome.IsValid
            });
        }
    }
}
