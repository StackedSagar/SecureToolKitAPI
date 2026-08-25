using SecureToolKitAPI.Application;
using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Contracts.KeyGeneration;
using SecureToolKitAPI.Contracts.Methods;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates cryptographic keys and secrets. Key material is produced by the cryptography layer;
    /// this controller only validates the request, selects the method and maps the result.
    /// </summary>
    /// <remarks>
    /// Responses contain secret material. Callers must treat generated keys as sensitive, keep them
    /// out of logs and out of source control.
    /// </remarks>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class KeyGenController(IKeyGenerationService keyGeneration) : ControllerBase
    {
        /// <summary>
        /// Lists the supported key-generation methods and their accepted key sizes.
        /// </summary>
        /// <returns>Returns one entry per supported method.</returns>
        [HttpGet("methods")]
        [ProducesResponseType<IEnumerable<KeyGenerationMethodResponse>>(StatusCodes.Status200OK)]
        public IActionResult GetMethods() =>
            Ok(keyGeneration.Methods.Select(method => new KeyGenerationMethodResponse
            {
                Name = method.Name,
                Aliases = method.Aliases,
                Description = method.Description,
                SupportedKeySizes = method.SupportedKeySizes,
                DefaultKeySize = method.DefaultKeySize
            }));

        /// <summary>
        /// Generates a symmetric AES key for use with the <c>aes-gcm</c> encryption method.
        ///  Shared Key maps to backend variable <c> Shared Key</c> (Base64).
        /// </summary>
        /// <param name="keySize">AES key size in bits (for example: 128, 192, 256).</param>
        /// <returns>Returns a generated AES key as Base64.</returns>
        [HttpGet("aes")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateAesKey(int keySize = 256) =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("aes", keySize)));

        /// <summary>
        /// Generates an RSA key pair for use with the <c>rsa-oaep</c> encryption method.
        /// </summary>
        /// <param name="keySize">RSA key size in bits. Valid values: 512, 1024, 2048, 3072, 4096.</param>
        /// <returns>Returns RSA public and private keys.</returns>
        /// <remarks>
        /// Sizes below 2048 bits remain available for backward compatibility and are reported with a
        /// warning, but the encryption and decryption endpoints reject them.
        /// </remarks>
        [HttpGet("rsa")]
        [ProducesResponseType<KeyPairResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateRsaKeys(int keySize = 2048) =>
            Ok(GeneratedKeyMapper.ToKeyPair(keyGeneration.Generate("rsa", keySize)));

        /// <summary>
        /// Generates an ECDH (Elliptic Curve Diffie-Hellman) key pair.
        /// </summary>
        /// <param name="keySize">Curve strength. Valid values: 256 (P-256), 384 (P-384), 521 (P-521).</param>
        /// <returns>
        /// Returns EC key pair used for key agreement.
        /// PublicKey maps to frontend variable <c>VITE_PUBLIC_KEY</c> (SPKI Base64).
        /// PrivateKey maps to backend variable <c>DecryptionKey</c> (PKCS#8 Base64).
        /// </returns>
        /// <remarks>
        /// The shared secret (for example <c>SharedKey</c> or <c>VITE_SHARED_KEY</c>) is derived later using ECDH on both sides,
        /// and is not directly returned by this endpoint. The <c>ecc-hillman</c> encryption method performs
        /// that agreement internally using a single-use ephemeral key pair.
        /// </remarks>
        [HttpGet("EccHillman")]
        [ProducesResponseType<KeyPairResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateEccHillman(int keySize = 256) =>
            Ok(GeneratedKeyMapper.ToKeyPair(keyGeneration.Generate("ecc-hillman", keySize)));

        /// <summary>
        /// Generates an ECDSA key pair for digital signatures.
        /// </summary>
        /// <param name="keySize">Curve strength. Valid values: 256 (P-256), 384 (P-384), 521 (P-521).</param>
        /// <returns>Returns ECDSA public and private keys.</returns>
        [HttpGet("EccDss")]
        [ProducesResponseType<KeyPairResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateEccDss(int keySize = 256) =>
            Ok(GeneratedKeyMapper.ToKeyPair(keyGeneration.Generate("ecc-dss", keySize)));

        /// <summary>
        /// Generates an HMAC-SHA256 secret for use with the <c>hmac-sha256</c> signature method.
        /// </summary>
        /// <param name="keySize">Secret size in bits. Valid values: 128, 256, 384, 512.</param>
        /// <returns>Returns a generated HMAC secret as Base64.</returns>
        [HttpGet("hmac")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateHmacSecret(int keySize = 256) =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("hmac", keySize)));

        /// <summary>
        /// Generates a general-purpose random secret.
        /// </summary>
        /// <param name="keySize">Secret size in bits. Valid values: 128, 192, 256, 384, 512, 1024.</param>
        /// <returns>Returns a generated random secret as Base64.</returns>
        /// <remarks>
        /// This is raw randomness for use as a token or salt. It is not bound to any algorithm; use the
        /// algorithm-specific endpoints when generating keys for encryption or signing.
        /// </remarks>
        [HttpGet("random")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateRandomSecret(int keySize = 256) =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("random", keySize)));

        /// <summary>
        /// Generates key material using any supported method, selected by name.
        /// </summary>
        /// <param name="method">
        /// Method name or alias, for example <c>aes</c>, <c>rsa</c>, <c>ecc-hillman</c>, <c>ecc-dss</c>,
        /// <c>hmac</c> or <c>random</c>. Matched case-insensitively.
        /// </param>
        /// <param name="request">Optional key size. Omit the body to use the method default.</param>
        /// <returns>Returns the generated key material for the selected method.</returns>
        [HttpPost("{method}")]
        [ProducesResponseType<GeneratedKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult Generate(
            string method,
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] KeyGenerationRequest? request = null)
        {
            var generated = keyGeneration.Generate(method, request?.KeySize);

            return Ok(GeneratedKeyMapper.ToGeneratedKey(method.Trim().ToLowerInvariant(), generated));
        }
    }
}
