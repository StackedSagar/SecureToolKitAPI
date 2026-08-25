using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>The hash functions this API will compute a digest with.</summary>
    /// <remarks>
    /// <para>
    /// The SHA-2 family is here because it is the family to use. <see cref="Md5"/> is here for one reason
    /// only: verifying a checksum that something else already published. It is cryptographically broken and
    /// every response that uses it says so.
    /// </para>
    /// <para>
    /// SHA-1 is deliberately absent. It is broken in the same way MD5 is, and MD5 already covers the one job
    /// a broken hash is still asked to do, so adding a second one would widen the surface without answering
    /// a need. SHA-3 is absent for a different reason: .NET exposes it only where the underlying platform
    /// provides it, so an endpoint offering it would work on some machines and fail on others.
    /// </para>
    /// <para>
    /// There is no bcrypt, scrypt, Argon2 or PBKDF2 here, and there should not be: those are password hashing
    /// functions with a deliberate cost factor, and putting them beside these would invite exactly the
    /// confusion the warnings on every response are written to prevent. None of the functions here is
    /// suitable for storing a password.
    /// </para>
    /// </remarks>
    public enum HashAlgorithmChoice
    {
        /// <summary>SHA-256, a 256-bit digest. The default, and the right choice absent a reason.</summary>
        Sha256,

        /// <summary>SHA-384, a 384-bit digest from the same construction as SHA-512, truncated.</summary>
        Sha384,

        /// <summary>SHA-512, a 512-bit digest. Often faster than SHA-256 on 64-bit hardware.</summary>
        Sha512,

        /// <summary>
        /// MD5, a 128-bit digest. Cryptographically broken: collisions can be produced at will. Offered for
        /// checking a published checksum, and for nothing else.
        /// </summary>
        Md5
    }

    /// <summary>How the caller's message is turned into the bytes that get hashed.</summary>
    /// <remarks>
    /// A hash is defined over bytes, not over text, so this is not a detail that can be left implicit: the
    /// same characters hashed as UTF-8 and as UTF-16 give different digests, and a file's checksum is over
    /// its bytes rather than over any text reading of them. Stating the format explicitly is what makes a
    /// digest from this API reproducible somewhere else.
    /// </remarks>
    public enum HashInputFormat
    {
        /// <summary>The message is text and is hashed as its UTF-8 bytes. The default.</summary>
        Text,

        /// <summary>The message is Base64 and is decoded to raw bytes before hashing.</summary>
        Base64,

        /// <summary>The message is hexadecimal and is decoded to raw bytes before hashing.</summary>
        Hex
    }

    /// <summary>How the finished digest is written down.</summary>
    /// <remarks>
    /// These are renderings of the same bytes and nothing more. A digest is not secret and not reversible, so
    /// the choice here is only about matching whatever you are comparing against: <c>sha256sum</c>,
    /// <c>md5sum</c> and <c>certutil</c> print lowercase hexadecimal, while <c>Content-Digest</c> headers and
    /// Subresource Integrity attributes carry Base64.
    /// </remarks>
    public enum DigestEncoding
    {
        /// <summary>Lowercase hexadecimal, as <c>sha256sum</c> and <c>md5sum</c> print. The default.</summary>
        Hex,

        /// <summary>Uppercase hexadecimal, as <c>certutil -hashfile</c> prints.</summary>
        HexUpper,

        /// <summary>Standard Base64, as Subresource Integrity and <c>Content-Digest</c> use.</summary>
        Base64
    }

    /// <summary>
    /// Options for computing a digest: which hash function, what the message is, how to read it and how to
    /// write the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The message is required but may be empty. Hashing nothing is a well-defined operation with a
    /// well-known answer for every one of these functions, so an empty message is honoured rather than
    /// refused; a missing message is a bad request, because it means the caller did not say what to hash.
    /// </para>
    /// <para>
    /// Validation happens in two steps because the two things being checked cost different amounts. The
    /// options and the presence of the message are checked by <see cref="Validate"/>, which touches nothing
    /// large. Decoding the message is done by <see cref="ReadInput"/>, which is where a malformed or
    /// oversized payload is reported, and which the caller invokes once so the message is never decoded
    /// twice.
    /// </para>
    /// </remarks>
    public sealed record HashSpec
    {
        /// <summary>
        /// Most bytes this API will hash in one request, one mebibyte.
        /// </summary>
        /// <remarks>
        /// A digest is computed over the whole message in memory, so this is a bound on what one request can
        /// ask the server to hold rather than a cryptographic limit. Hashing a large file is a job for
        /// <c>sha256sum</c> on the machine that has the file, not for an HTTP round trip.
        /// </remarks>
        public const int MaximumInputBytes = 1_048_576;

        /// <summary>
        /// Longest message string this API will accept, before decoding.
        /// </summary>
        /// <remarks>
        /// Checked before anything is decoded, so an absurd payload is refused without first being turned
        /// into bytes. It is deliberately looser than <see cref="MaximumInputBytes"/>, because Base64 and
        /// hexadecimal both spend more characters than the bytes they carry; the byte count is what actually
        /// decides, and it is checked after decoding.
        /// </remarks>
        public const int MaximumInputCharacters = 4 * MaximumInputBytes;

        /// <summary>The hash function. Defaults to <see cref="HashAlgorithmChoice.Sha256"/>.</summary>
        public HashAlgorithmChoice Algorithm { get; init; } = HashAlgorithmChoice.Sha256;

        /// <summary>How the message is read. Defaults to <see cref="HashInputFormat.Text"/>.</summary>
        public HashInputFormat InputFormat { get; init; } = HashInputFormat.Text;

        /// <summary>How the digest is written. Defaults to <see cref="DigestEncoding.Hex"/>.</summary>
        public DigestEncoding Encoding { get; init; } = DigestEncoding.Hex;

        /// <summary>
        /// The message to hash, read according to <see cref="InputFormat"/>. Required; may be empty. This is
        /// the caller's own data and is never echoed back in the response.
        /// </summary>
        public string? Message { get; init; }

        /// <summary>The hash function's name as the standard that defines it spells it.</summary>
        public string AlgorithmName => Algorithm switch
        {
            HashAlgorithmChoice.Sha384 => "SHA-384",
            HashAlgorithmChoice.Sha512 => "SHA-512",
            HashAlgorithmChoice.Md5 => "MD5",
            _ => "SHA-256"
        };

        /// <summary>Size of the digest this function produces, in bits.</summary>
        public int DigestSizeBits => DigestSizeBitsOf(Algorithm);

        /// <summary>
        /// Whether the chosen function is cryptographically broken, meaning an attacker can produce two
        /// different messages with the same digest.
        /// </summary>
        /// <remarks>
        /// This is reported rather than inferred from the name, so a caller can refuse a broken digest
        /// programmatically instead of having to keep its own list of which functions have fallen.
        /// </remarks>
        public bool IsCryptographicallyBroken => IsBroken(Algorithm);

        /// <summary>The hash functions this API will compute, strongest first.</summary>
        /// <remarks>
        /// The broken one is last on purpose: this order is what the catalogue endpoint serves, and a caller
        /// reading down the list reaches the functions worth using before it reaches the one that is not.
        /// </remarks>
        public static IReadOnlyList<HashAlgorithmChoice> SupportedAlgorithms { get; } =
        [
            HashAlgorithmChoice.Sha512,
            HashAlgorithmChoice.Sha384,
            HashAlgorithmChoice.Sha256,
            HashAlgorithmChoice.Md5
        ];

        /// <summary>Size of the digest a given function produces, in bits.</summary>
        /// <param name="algorithm">The hash function.</param>
        public static int DigestSizeBitsOf(HashAlgorithmChoice algorithm) => algorithm switch
        {
            HashAlgorithmChoice.Sha384 => 384,
            HashAlgorithmChoice.Sha512 => 512,
            HashAlgorithmChoice.Md5 => 128,
            _ => 256
        };

        /// <summary>Whether a given function is cryptographically broken.</summary>
        /// <param name="algorithm">The hash function.</param>
        public static bool IsBroken(HashAlgorithmChoice algorithm) => algorithm is HashAlgorithmChoice.Md5;

        /// <summary>Validates the options and that a message was supplied.</summary>
        /// <exception cref="CryptographicRequestException">
        /// An option is not supported, the message is missing, or the message is longer than this API will
        /// accept.
        /// </exception>
        /// <remarks>
        /// Nothing is decoded here. Whether the message is well formed for the chosen input format is decided
        /// by <see cref="ReadInput"/>, so a caller that only wants to check the options does not pay for
        /// decoding the payload.
        /// </remarks>
        public void Validate()
        {
            if (!Enum.IsDefined(Algorithm))
            {
                throw new CryptographicRequestException("The requested hash algorithm is not supported.");
            }

            if (!Enum.IsDefined(InputFormat))
            {
                throw new CryptographicRequestException("The requested input format is not supported.");
            }

            if (!Enum.IsDefined(Encoding))
            {
                throw new CryptographicRequestException("The requested digest encoding is not supported.");
            }

            // Null and empty are different here. An empty message has a digest; a missing one means the
            // caller never said what to hash.
            if (Message is null)
            {
                throw new CryptographicRequestException("The message is required.");
            }

            if (Message.Length > MaximumInputCharacters)
            {
                throw new CryptographicRequestException(
                    $"The message must be {MaximumInputCharacters} characters or fewer.");
            }
        }

        /// <summary>
        /// Decodes the message into the bytes that will be hashed.
        /// </summary>
        /// <returns>The bytes to hash, which may be empty.</returns>
        /// <exception cref="CryptographicRequestException">
        /// The message is missing, is not valid for the chosen input format, or decodes to more bytes than
        /// this API will hash.
        /// </exception>
        /// <remarks>
        /// Failures name the format that was expected and never echo the message, because the message is the
        /// caller's data and may well be a secret they are fingerprinting.
        /// </remarks>
        public byte[] ReadInput()
        {
            if (Message is null)
            {
                throw new CryptographicRequestException("The message is required.");
            }

            var input = InputFormat switch
            {
                HashInputFormat.Base64 => FromBase64(Message),
                HashInputFormat.Hex => FromHex(Message),
                _ => System.Text.Encoding.UTF8.GetBytes(Message)
            };

            if (input.Length > MaximumInputBytes)
            {
                throw new CryptographicRequestException(
                    $"The message must decode to {MaximumInputBytes} bytes or fewer.");
            }

            return input;
        }

        /// <summary>Describes what will be hashed and how the result will be written, for the response.</summary>
        /// <param name="inputByteCount">Bytes that were hashed.</param>
        /// <param name="digestLength">Characters in the rendered digest.</param>
        /// <returns>A caller-safe description that never contains the message or the digest.</returns>
        public string Describe(int inputByteCount, int digestLength) =>
            $"{AlgorithmName} digest of {inputByteCount} bytes of {DescribeInputFormat()}, "
            + $"{DigestSizeBits} bits written as {DescribeEncoding()} ({digestLength} characters)";

        /// <summary>Caller-facing description of how the message was read.</summary>
        public string DescribeInputFormat() => InputFormat switch
        {
            HashInputFormat.Base64 => "Base64 decoded input",
            HashInputFormat.Hex => "hexadecimal decoded input",
            _ => "UTF-8 text"
        };

        /// <summary>Caller-facing description of how the digest was written.</summary>
        public string DescribeEncoding() => Encoding switch
        {
            DigestEncoding.HexUpper => "uppercase hexadecimal",
            DigestEncoding.Base64 => "Base64",
            _ => "lowercase hexadecimal"
        };

        /// <summary>Decodes a Base64 message, reporting a safe error when it is malformed.</summary>
        /// <param name="message">The caller's message.</param>
        private static byte[] FromBase64(string message)
        {
            if (!Base64Text.TryDecode(message, out var decoded))
            {
                throw new CryptographicRequestException(
                    "The message is not valid Base64. Send it as text by leaving the input format unset, or "
                    + "correct the encoding.");
            }

            return decoded;
        }

        /// <summary>Decodes a hexadecimal message, reporting a safe error when it is malformed.</summary>
        /// <param name="message">The caller's message.</param>
        /// <remarks>
        /// An odd number of digits is the mistake that actually happens, usually from a truncated copy, so it
        /// is worth naming separately from a bad character.
        /// </remarks>
        private static byte[] FromHex(string message)
        {
            var trimmed = message.Trim();

            if (trimmed.Length % 2 != 0)
            {
                throw new CryptographicRequestException(
                    "The message is not valid hexadecimal: it has an odd number of digits, so the last byte "
                    + "is incomplete.");
            }

            try
            {
                return Convert.FromHexString(trimmed);
            }
            catch (FormatException)
            {
                throw new CryptographicRequestException(
                    "The message is not valid hexadecimal. Send it as text by leaving the input format unset, "
                    + "or correct the encoding.");
            }
        }
    }

    /// <summary>
    /// Reads the caller-facing spelling of the hashing options and turns it into the corresponding option, so
    /// an unknown value is reported as a bad request rather than silently falling back to a default.
    /// </summary>
    /// <remarks>
    /// Matching ignores case, hyphens, underscores and spaces, so <c>SHA-256</c>, <c>sha256</c> and
    /// <c>SHA_256</c> all resolve to the same function. An omitted value means "use the default".
    /// </remarks>
    public static class HashOptions
    {
        /// <summary>Resolves a hash function name such as <c>sha256</c> or <c>md5</c>.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved function.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported function.</exception>
        /// <remarks>
        /// <c>sha1</c>, <c>sha3-256</c>, <c>bcrypt</c> and <c>argon2</c> all land here as unsupported names,
        /// which is the intended answer in each case: substituting a different function for the one that was
        /// asked for would produce a digest the caller cannot use and cannot explain.
        /// </remarks>
        public static HashAlgorithmChoice ParseAlgorithm(string? value) =>
            OptionName.Parse(value, HashAlgorithmChoice.Sha256, "hash algorithm");

        /// <summary>Resolves an input format name such as <c>text</c>, <c>base64</c> or <c>hex</c>.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved format.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported format.</exception>
        public static HashInputFormat ParseInputFormat(string? value) =>
            OptionName.Parse(value, HashInputFormat.Text, "input format");

        /// <summary>Resolves a digest encoding name such as <c>hex</c> or <c>base64</c>.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved encoding.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported encoding.</exception>
        public static DigestEncoding ParseEncoding(string? value) =>
            OptionName.Parse(value, DigestEncoding.Hex, "digest encoding");
    }
}
