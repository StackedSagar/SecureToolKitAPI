using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Hashing
{
    /// <summary>
    /// Computes message digests with the .NET one-shot hashing APIs, and describes the functions it will
    /// compute.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class produces no secret and takes no key, which makes it the odd one out in this project and
    /// worth being explicit about. A digest is a one-way fingerprint of a message: the same message always
    /// gives the same digest, two callers hashing the same thing get the same answer, and no amount of the
    /// digest recovers the message. Nothing here protects confidentiality, so every response carries warnings
    /// saying as much.
    /// </para>
    /// <para>
    /// Every digest comes from <see cref="SHA256"/>, <see cref="SHA384"/>, <see cref="SHA512"/> or
    /// <see cref="MD5"/> through their static <c>HashData</c> methods. No hash function is implemented here,
    /// and none should be: these are the platform's implementations, and a hand-rolled one that differs in the
    /// last block produces digests that silently fail to match anything else in the world.
    /// </para>
    /// <para>
    /// The input is read as bytes according to the caller's stated format, because a hash is defined over
    /// bytes and not over text. That is what allows a digest computed here to match one computed by
    /// <c>sha256sum</c> or <c>md5sum</c> over the same file, which is the only reason MD5 is offered at all.
    /// </para>
    /// <para>
    /// The class is stateless and therefore safe to share as a singleton. The caller's message is hashed and
    /// dropped: it is never logged, never retained and never returned, and the result reports only how many
    /// bytes there were.
    /// </para>
    /// </remarks>
    public sealed class HashGenerator : IHashGenerator
    {
        /// <summary>
        /// The catalogue, built once. Fixed data with no caller input in it, so there is nothing to rebuild
        /// per request.
        /// </summary>
        private static readonly IReadOnlyList<HashAlgorithmInfo> Catalogue = BuildCatalogue();

        /// <summary>
        /// Advisories that belong on every digest regardless of the function used, ordered so the mistake that
        /// matters most comes first.
        /// </summary>
        private static readonly string[] UniversalWarnings =
        [
            "A hash is not encryption. There is no key, there is nothing to decrypt, and the same input always "
            + "produces the same digest. Publishing a digest of something short or guessable — a password, a "
            + "phone number, an email address, an account number — does not hide it: an attacker hashes "
            + "candidates until one matches. To make a message unreadable, encrypt it.",
            "Never store a password as one of these digests, even salted. These functions are built to be "
            + "fast, which is precisely what makes them wrong for the job: a modern graphics card computes "
            + "billions of them per second. Use bcrypt, scrypt, Argon2 or PBKDF2, each of which has a "
            + "deliberate cost factor and a per-password salt.",
            "A digest shows that content has not changed; it does not show who produced it. Anyone can hash "
            + "anything, so a digest alongside the data it describes proves nothing against an attacker who "
            + "can alter both. For authenticity you need a secret or a key: HMAC-SHA256 at "
            + "/api/signature/hmac-sha256, or a signature at /api/signature/sign."
        ];

        /// <inheritdoc />
        public ComputedHash ComputeHash(HashSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            // Decoded once, here. The spec validates its options without touching the payload so that a
            // malformed message is the only thing this step can still fail on.
            var input = spec.ReadInput();
            var digest = Digest(spec.Algorithm, input);
            var rendered = Render(digest, spec.Encoding);

            return new ComputedHash
            {
                Algorithm = spec.AlgorithmName,
                DigestSizeBits = spec.DigestSizeBits,
                Digest = rendered,
                Encoding = spec.DescribeEncoding(),
                InputFormat = spec.DescribeInputFormat(),
                InputByteCount = input.Length,
                IsCryptographicallyBroken = spec.IsCryptographicallyBroken,
                Composition = spec.Describe(input.Length, rendered.Length),
                Warnings = Warnings(spec.Algorithm)
            };
        }

        /// <inheritdoc />
        public IReadOnlyList<HashAlgorithmInfo> HashAlgorithms() => Catalogue;

        /// <summary>
        /// Computes the raw digest bytes with the platform's implementation of the chosen function.
        /// </summary>
        /// <param name="algorithm">The hash function.</param>
        /// <param name="input">The bytes to hash; may be empty.</param>
        /// <returns>The digest bytes.</returns>
        /// <remarks>
        /// The one-shot <c>HashData</c> form is used rather than creating an instance, so there is no object
        /// to dispose, nothing held between calls and nothing shared between concurrent requests.
        /// </remarks>
        private static byte[] Digest(HashAlgorithmChoice algorithm, byte[] input) => algorithm switch
        {
            HashAlgorithmChoice.Sha384 => SHA384.HashData(input),
            HashAlgorithmChoice.Sha512 => SHA512.HashData(input),
            HashAlgorithmChoice.Md5 => Md5Digest(input),
            _ => SHA256.HashData(input)
        };

        /// <summary>Computes an MD5 digest, knowingly and for checksum compatibility only.</summary>
        /// <param name="input">The bytes to hash; may be empty.</param>
        /// <returns>The 16-byte digest.</returns>
        /// <remarks>
        /// Separated out so the suppression sits on this call alone rather than over the whole selection, and
        /// so the reason is written next to the thing being excused. MD5 is here so a caller can verify a
        /// digest that something else already published; every response computed with it reports
        /// <c>IsCryptographicallyBroken</c> and carries warnings naming what it must not be used for.
        /// </remarks>
#pragma warning disable CA5351 // Do not use broken cryptographic algorithms: deliberate, see remarks.
        private static byte[] Md5Digest(byte[] input) => MD5.HashData(input);
#pragma warning restore CA5351

        /// <summary>Renders the digest bytes as text.</summary>
        /// <param name="digest">The digest bytes.</param>
        /// <param name="encoding">How to write them.</param>
        /// <returns>The rendered digest.</returns>
        /// <remarks>
        /// Lowercase hexadecimal is the default because that is what <c>sha256sum</c> and <c>md5sum</c> print,
        /// and a digest that has to be case-corrected before it can be compared is a digest that will be
        /// compared wrongly at least once.
        /// </remarks>
        private static string Render(byte[] digest, DigestEncoding encoding) => encoding switch
        {
            DigestEncoding.HexUpper => Convert.ToHexString(digest),
            DigestEncoding.Base64 => Base64Text.Encode(digest),
            _ => Convert.ToHexString(digest).ToLowerInvariant()
        };

        /// <summary>Builds the advisories for a digest.</summary>
        /// <param name="algorithm">The function that produced it.</param>
        /// <returns>The universal advisories, preceded by any specific to a broken function.</returns>
        /// <remarks>
        /// The advisory for a broken function goes first, ahead of the general ones, because a caller who
        /// reads only the first line should read the one that applies to the digest they are holding.
        /// </remarks>
        private static IReadOnlyList<string> Warnings(HashAlgorithmChoice algorithm)
        {
            if (algorithm is not HashAlgorithmChoice.Md5)
            {
                return UniversalWarnings;
            }

            return
            [
                "MD5 is cryptographically broken. Two different messages with the same MD5 digest can be "
                + "produced on a laptop in seconds, and have been demonstrated publicly since 2004. Never use "
                + "it for a signature, a certificate, a security token, or deduplication where someone could "
                + "benefit from a collision.",
                "MD5 is offered here for one purpose: checking a digest that something else already published, "
                + "such as a download checksum from a source you already trust. It answers 'did this arrive "
                + "intact' and not 'is this the file the publisher meant', because an attacker who can replace "
                + "the file can replace the checksum beside it. Prefer SHA-256 wherever the other side "
                + "supports it.",
                .. UniversalWarnings
            ];
        }

        /// <summary>Builds the catalogue of supported functions.</summary>
        /// <returns>The catalogue in <see cref="HashSpec.SupportedAlgorithms"/> order, strongest first.</returns>
        private static IReadOnlyList<HashAlgorithmInfo> BuildCatalogue()
        {
            var defaults = new HashSpec();

            return
            [
                .. HashSpec.SupportedAlgorithms.Select(algorithm =>
                {
                    var spec = defaults with { Algorithm = algorithm };

                    return new HashAlgorithmInfo
                    {
                        Algorithm = spec.AlgorithmName,
                        Name = spec.AlgorithmName,
                        DigestSizeBits = spec.DigestSizeBits,
                        IsDefault = algorithm == defaults.Algorithm,
                        IsCryptographicallyBroken = spec.IsCryptographicallyBroken,
                        Notes = Notes(algorithm)
                    };
                })
            ];
        }

        /// <summary>What each function is suited to, in plain language, for the catalogue.</summary>
        /// <param name="algorithm">The hash function.</param>
        private static string Notes(HashAlgorithmChoice algorithm) => algorithm switch
        {
            HashAlgorithmChoice.Sha512 =>
                "Strongest here, and often faster than SHA-256 on 64-bit hardware because it works in 64-bit "
                + "words. Choose it when the digest is being stored or transmitted somewhere that a longer "
                + "value costs nothing.",
            HashAlgorithmChoice.Sha384 =>
                "SHA-512 truncated to 384 bits. Chosen mainly to match a specification that names it, such as "
                + "a TLS cipher suite or a certificate profile, rather than for a security reason of its own.",
            HashAlgorithmChoice.Md5 =>
                "Broken. Collisions are trivial to produce. Present only so a caller can verify a checksum "
                + "that something else already published; never for signatures, certificates or anything an "
                + "attacker benefits from colliding.",
            _ =>
                "The default and the right choice absent a specific reason. Widely supported, no known "
                + "practical weakness, and the function that sha256sum, Subresource Integrity and most "
                + "protocols in current use expect."
        };
    }
}
