using SecureToolKitAPI.Contracts.Hashing;
using SecureToolKitAPI.Cryptography.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureToolKitAPI.Controllers
{
    /// <summary>
    /// Computes a message digest with a chosen hash function, and lists the functions on offer. Hashing lives
    /// in <see cref="IHashGenerator"/>; this controller maps the request and maps the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This controller is the one place in the API that produces no secret and takes no key. A digest is a
    /// one-way fingerprint of a message: the same message always gives the same digest, there is nothing to
    /// decrypt, and the message cannot be recovered from the result. Every response says so, because hashing
    /// is the operation most often mistaken for encryption. To make a message unreadable, use
    /// <c>/api/encryption/encrypt</c>; to prove who produced it, use <c>/api/signature</c>.
    /// </para>
    /// <para>
    /// The generation endpoints are POST because the message travels in the body, where a URL's usual haunts —
    /// server logs, proxy logs, browser history — cannot reach it. The message may be a secret the caller is
    /// fingerprinting, so even though a digest is not secret, the input to it is treated as if it were: it is
    /// never logged and never echoed back. The catalogue at <c>GET /api/hash/algorithms</c> carries no caller
    /// data, so it is safe over GET.
    /// </para>
    /// <para>
    /// There is a general route that takes the function by name, and two convenience routes that fix the
    /// function in the URL. <c>/sha256</c> is the one to reach for; <c>/md5</c> exists only so a caller can
    /// verify a checksum that something else already published, and every MD5 response says that it is
    /// cryptographically broken and unfit for anything adversarial.
    /// </para>
    /// <para>
    /// Every endpoint accepts an omitted body so that a missing message is reported as this API's own problem
    /// response — "The message is required." — rather than as a framework binding failure. A malformed or
    /// oversized message is reported the same way, naming the format that was expected without ever repeating
    /// the message back.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api/hash")]
    [Produces("application/json")]
    public class HashController(IHashGenerator hashes) : ControllerBase
    {
        /// <summary>
        /// Computes the digest of a message with the requested hash function.
        /// </summary>
        /// <param name="request">
        /// The function, the message, and how to read and render it. Omit the algorithm for SHA-256; the
        /// message is required.
        /// </param>
        /// <returns>Returns the digest and the figures describing it.</returns>
        /// <remarks>
        /// The algorithm is chosen by name here. To pin it in the URL instead, use <c>/api/hash/sha256</c> or
        /// <c>/api/hash/md5</c>.
        /// </remarks>
        [HttpPost]
        [ProducesResponseType<HashResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult ComputeHash(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] HashRequest? request = null) =>
            Ok(ToResponse(hashes.ComputeHash(ToSpec(request))));

        /// <summary>
        /// Computes the SHA-256 digest of a message.
        /// </summary>
        /// <param name="request">The message, and how to read and render it. The message is required.</param>
        /// <returns>Returns the digest and the figures describing it.</returns>
        /// <remarks>
        /// The function is fixed by the route, so there is no algorithm to send. SHA-256 is the default and
        /// the right choice absent a specific reason to use something else.
        /// </remarks>
        [HttpPost("sha256")]
        [ProducesResponseType<HashResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult ComputeSha256(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] FixedHashRequest? request = null) =>
            Ok(ToResponse(hashes.ComputeHash(ToSpec(request, HashAlgorithmChoice.Sha256))));

        /// <summary>
        /// Computes the MD5 digest of a message, for checksum compatibility only.
        /// </summary>
        /// <param name="request">The message, and how to read and render it. The message is required.</param>
        /// <returns>
        /// Returns the digest, with warnings that MD5 is cryptographically broken and unfit for signatures,
        /// certificates, tamper resistance or password storage.
        /// </returns>
        /// <remarks>
        /// MD5 is offered so a caller can verify a digest that something else already published, such as a
        /// download checksum from a source already trusted. It answers "did this arrive intact" and not "is
        /// this what the publisher meant". Prefer <c>/api/hash/sha256</c> wherever the other side supports it.
        /// </remarks>
        [HttpPost("md5")]
        [ProducesResponseType<HashResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
        public IActionResult ComputeMd5(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] FixedHashRequest? request = null) =>
            Ok(ToResponse(hashes.ComputeHash(ToSpec(request, HashAlgorithmChoice.Md5))));

        /// <summary>
        /// Lists the hash functions this API will compute, strongest first.
        /// </summary>
        /// <returns>Returns the catalogue: each function's name, digest size, and whether it is broken.</returns>
        /// <remarks>
        /// A GET because it carries no caller data and no secret — only the fixed list of functions and their
        /// properties, which a caller can read to discover the accepted names rather than guessing at them.
        /// </remarks>
        [HttpGet("algorithms")]
        [ProducesResponseType<IReadOnlyList<HashAlgorithmResponse>>(StatusCodes.Status200OK)]
        public IActionResult HashAlgorithms() =>
            Ok(hashes.HashAlgorithms().Select(algorithm => ToResponse(algorithm)).ToArray());

        /// <summary>Maps the general hash request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <remarks>
        /// A <c>null</c> request leaves the message <c>null</c> on purpose, so the generator reports the
        /// missing message as a domain error rather than this mapper inventing an empty one.
        /// </remarks>
        private static HashSpec ToSpec(HashRequest? request)
        {
            var defaults = new HashSpec();

            if (request is null)
            {
                return defaults;
            }

            return new HashSpec
            {
                Algorithm = HashOptions.ParseAlgorithm(request.Algorithm),
                InputFormat = HashOptions.ParseInputFormat(request.InputFormat),
                Encoding = HashOptions.ParseEncoding(request.Encoding),
                Message = request.Message
            };
        }

        /// <summary>Maps a fixed-algorithm request onto the generator's options.</summary>
        /// <param name="request">The request, or <c>null</c> when the body was omitted.</param>
        /// <param name="algorithm">The function the route has already chosen.</param>
        /// <remarks>
        /// The algorithm comes from the route rather than the body, so there is no algorithm field here to
        /// contradict it. Everything else is mapped exactly as the general route maps it, through the same
        /// option parsers, so the two routes cannot drift apart in how they read a format or an encoding.
        /// </remarks>
        private static HashSpec ToSpec(FixedHashRequest? request, HashAlgorithmChoice algorithm)
        {
            if (request is null)
            {
                return new HashSpec { Algorithm = algorithm };
            }

            return new HashSpec
            {
                Algorithm = algorithm,
                InputFormat = HashOptions.ParseInputFormat(request.InputFormat),
                Encoding = HashOptions.ParseEncoding(request.Encoding),
                Message = request.Message
            };
        }

        /// <summary>Maps a computed digest onto the response contract.</summary>
        /// <param name="hash">What the generator produced.</param>
        private static HashResponse ToResponse(ComputedHash hash) => new()
        {
            Algorithm = hash.Algorithm,
            DigestSizeBits = hash.DigestSizeBits,
            Digest = hash.Digest,
            Encoding = hash.Encoding,
            InputFormat = hash.InputFormat,
            InputByteCount = hash.InputByteCount,
            IsCryptographicallyBroken = hash.IsCryptographicallyBroken,
            Composition = hash.Composition,
            Warnings = hash.Warnings
        };

        /// <summary>Maps a catalogue entry onto the response contract.</summary>
        /// <param name="algorithm">What the generator listed.</param>
        private static HashAlgorithmResponse ToResponse(HashAlgorithmInfo algorithm) => new()
        {
            Algorithm = algorithm.Algorithm,
            Name = algorithm.Name,
            DigestSizeBits = algorithm.DigestSizeBits,
            IsDefault = algorithm.IsDefault,
            IsCryptographicallyBroken = algorithm.IsCryptographicallyBroken,
            Notes = algorithm.Notes
        };
    }
}
