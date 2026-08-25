using SecureToolKitAPI.Application.Abstractions;
using SecureToolKitAPI.Contracts.KeyGeneration;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Generates the keys used to encrypt and authenticate data: AES keys, RSA key pairs, HMAC keys,
    /// general-purpose secrets and salts. Every value is produced by the cryptography layer; this
    /// controller validates the request, selects the generator and maps the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These endpoints use POST with an optional body. No key size and no generated value passes through
    /// the URL, so nothing reaches a server or proxy access log, and no response is cacheable by default.
    /// </para>
    /// <para>
    /// Every response except the salt contains secret material. Callers must treat it as sensitive: it is
    /// not logged here, and it must not be logged, cached or committed downstream.
    /// </para>
    /// <para>
    /// The equivalent GET routes under <c>/api/keygen</c> predate these endpoints and continue to work
    /// unchanged. They are kept for backward compatibility; new callers should prefer these.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/encryption")]
    [Produces("application/json")]
    public class EncryptionKeyGeneratorController(
        IKeyGenerationService keyGeneration,
        ISaltGenerator salts) : ControllerBase
    {
        /// <summary>The method used when a caller asks for an encryption key without naming one.</summary>
        private const string DefaultMethod = "aes";

        /// <summary>
        /// Generates key material for any supported method, named in the body.
        /// </summary>
        /// <param name="request">
        /// Method and key size. Omit the body for the default: a 256-bit AES key.
        /// </param>
        /// <returns>Returns the generated key material for the selected method.</returns>
        /// <remarks>
        /// This is the general-purpose entry point, for callers that choose the algorithm at run time. The
        /// endpoints below are shortcuts to the same generators with the method already decided. Method
        /// names and the sizes each one accepts are listed by <c>GET /api/keygen/methods</c>.
        /// </remarks>
        [HttpPost("encryption-key")]
        [ProducesResponseType<GeneratedKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateEncryptionKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] EncryptionKeyRequest? request = null)
        {
            var method = Normalize(request?.Method);

            return Ok(GeneratedKeyMapper.ToGeneratedKey(
                method,
                keyGeneration.Generate(method, request?.KeySize)));
        }

        /// <summary>
        /// Generates a symmetric AES key for use with the <c>aes-gcm</c> encryption method.
        /// </summary>
        /// <param name="request">
        /// Key size in bits: 128, 192 or 256. Omit the body for 256.
        /// </param>
        /// <returns>Returns the AES key as Base64.</returns>
        /// <remarks>
        /// All three sizes are sound. 256 is the default because the cost difference is negligible at this
        /// scale and it needs no revisiting later.
        /// </remarks>
        [HttpPost("aes")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateAesKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] KeyGenerationRequest? request = null) =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("aes", request?.KeySize)));

        /// <summary>
        /// Generates a 256-bit AES key.
        /// </summary>
        /// <returns>Returns a 256-bit AES key as Base64.</returns>
        /// <remarks>
        /// The size is fixed, so there is nothing to send and nothing to get wrong. Use
        /// <c>POST /api/encryption/aes</c> when the size has to be chosen.
        /// </remarks>
        [HttpPost("aes-256")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        public IActionResult GenerateAes256Key() =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("aes", keySizeBits: 256)));

        /// <summary>
        /// Generates an RSA key pair for use with the <c>rsa-oaep</c> encryption method.
        /// </summary>
        /// <param name="request">
        /// Key size in bits: 512, 1024, 2048, 3072 or 4096. Omit the body for 2048.
        /// </param>
        /// <returns>Returns the RSA public and private keys.</returns>
        /// <remarks>
        /// Sizes below 2048 bits remain available for backward compatibility and are returned with a
        /// warning, but the encryption and decryption endpoints reject them.
        /// </remarks>
        [HttpPost("rsa")]
        [ProducesResponseType<KeyPairResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateRsaKeyPair(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] KeyGenerationRequest? request = null) =>
            Ok(GeneratedKeyMapper.ToKeyPair(keyGeneration.Generate("rsa", request?.KeySize)));

        /// <summary>
        /// Generates an HMAC key for use with the <c>hmac-sha256</c> signature method.
        /// </summary>
        /// <param name="request">
        /// Key size in bits: 128, 256, 384 or 512. Omit the body for 256.
        /// </param>
        /// <returns>Returns the HMAC key as Base64.</returns>
        /// <remarks>
        /// An HMAC key is symmetric, so whoever can verify a message with it can also produce one. It
        /// proves that a message came from someone holding the key; it does not keep the message private.
        /// </remarks>
        [HttpPost("hmac")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateHmacKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] KeyGenerationRequest? request = null) =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("hmac", request?.KeySize)));

        /// <summary>
        /// Generates a general-purpose secret that is not bound to any algorithm.
        /// </summary>
        /// <param name="request">
        /// Secret size in bits: 128, 192, 256, 384, 512 or 1024. Omit the body for 256.
        /// </param>
        /// <returns>Returns the secret as Base64.</returns>
        /// <remarks>
        /// This is raw randomness, for a value that is compared rather than used as a key. The encryption
        /// endpoints reject it: they require a key generated for the algorithm they were asked to use.
        /// </remarks>
        [HttpPost("secret")]
        [ProducesResponseType<SymmetricKeyResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateSecretKey(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] KeyGenerationRequest? request = null) =>
            Ok(GeneratedKeyMapper.ToSymmetric(keyGeneration.Generate("random", request?.KeySize)));

        /// <summary>
        /// Generates a salt: random bytes that make an input unique before it is hashed.
        /// </summary>
        /// <param name="request">
        /// Size in bytes and encoding. Omit the body for 16 bytes, or 128 bits, Base64 encoded.
        /// </param>
        /// <returns>Returns the salt with the rules for using it.</returns>
        /// <remarks>
        /// A salt is the one value here that is not secret. It exists for uniqueness, not confidentiality:
        /// it must be stored alongside the hash it was used for, and a new one must be generated for every
        /// value hashed.
        /// </remarks>
        [HttpPost("salt")]
        [ProducesResponseType<SaltResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult GenerateSalt(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] SaltRequest? request = null) =>
            Ok(GeneratedKeyMapper.ToSalt(salts.Generate(ToSpec(request))));

        /// <summary>
        /// Normalizes the method name for the response, so the same name is reported however it was
        /// spelled. Whether the name resolves to a generator is decided by the registry, not here.
        /// </summary>
        /// <param name="method">Caller-supplied method name, or <c>null</c> to accept the default.</param>
        private static string Normalize(string? method) =>
            string.IsNullOrWhiteSpace(method) ? DefaultMethod : method.Trim().ToLowerInvariant();

        /// <summary>Maps the optional salt request to generator options.</summary>
        /// <param name="request">The request body, or <c>null</c> when it was omitted.</param>
        private static SaltSpec ToSpec(SaltRequest? request)
        {
            var defaults = new SaltSpec();

            if (request is null)
            {
                return defaults;
            }

            return new SaltSpec
            {
                Bytes = request.Bytes ?? defaults.Bytes,
                Encoding = DeveloperSecretOptions.ParseEncoding(request.Encoding, defaults.Encoding)
            };
        }
    }
}
