using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Turns randomness into the text forms the developer-secret endpoints hand back, and names the
    /// alphabets they sample from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Encoding is not encryption and is not treated as such anywhere here: these helpers only change how
    /// the same random bits are written down. All randomness comes from
    /// <see cref="RandomNumberGenerator"/>, and the raw buffers are cleared once the text has been built.
    /// </para>
    /// <para>
    /// The character sets are taken from <see cref="PasswordCharsets"/> rather than restated, so there is
    /// one definition of "the digits" and "the letters" in the codebase.
    /// </para>
    /// </remarks>
    internal static class SecretText
    {
        /// <summary>Digits and both letter cases, 62 symbols, in the conventional order.</summary>
        internal const string Base62 =
            PasswordCharsets.Digits + PasswordCharsets.Uppercase + PasswordCharsets.Lowercase;

        /// <summary>The URL-safe Base64 alphabet, 64 symbols, in RFC 4648 order.</summary>
        internal const string Base64UrlAlphabet =
            PasswordCharsets.Uppercase + PasswordCharsets.Lowercase + PasswordCharsets.Digits + "-_";

        /// <summary>Lowercase hexadecimal digits.</summary>
        internal const string HexLower = "0123456789abcdef";

        /// <summary>Uppercase hexadecimal digits.</summary>
        internal const string HexUpper = "0123456789ABCDEF";

        /// <summary>
        /// Crockford's Base32 alphabet, 32 symbols: the digits and the uppercase letters except I, L, O
        /// and U. Intended for values a person reads off a screen and types back in, where 1/I/l and
        /// 0/O are the mistakes that actually happen; U is dropped so the alphabet cannot spell an
        /// unfortunate word.
        /// </summary>
        internal const string Crockford32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        /// <summary>
        /// Draws random bytes and renders them as text.
        /// </summary>
        /// <param name="bytes">How many random bytes to draw.</param>
        /// <param name="encoding">How to render them. Not <see cref="SecretEncoding.Base62"/>.</param>
        /// <returns>The rendered text, carrying eight bits of entropy per byte drawn.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <see cref="SecretEncoding.Base62"/> was requested. Raw bytes cannot be re-based into 62 symbols
        /// without bias, so a Base62 value is sampled with <see cref="Sample"/> instead.
        /// </exception>
        internal static string Encode(int bytes, SecretEncoding encoding)
        {
            var material = RandomNumberGenerator.GetBytes(bytes);

            try
            {
                return encoding switch
                {
                    SecretEncoding.Base64Url => ToBase64Url(material),
                    SecretEncoding.Base64 => Convert.ToBase64String(material),
                    SecretEncoding.Hex => Convert.ToHexString(material).ToLowerInvariant(),
                    SecretEncoding.HexUpper => Convert.ToHexString(material),
                    _ => throw new ArgumentOutOfRangeException(
                        nameof(encoding), "Base62 values are sampled from the alphabet, not encoded from bytes.")
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
            }
        }

        /// <summary>
        /// Draws the requested amount of randomness and renders it, returning the text together with the
        /// entropy it carries.
        /// </summary>
        /// <param name="bytes">Requested strength in bytes.</param>
        /// <param name="encoding">How the value is rendered.</param>
        /// <returns>The rendered text and the entropy of the process that produced it.</returns>
        /// <remarks>
        /// <see cref="SecretEncoding.Base62"/> cannot be produced by re-basing raw bytes without bias, so it
        /// is sampled character by character instead — enough characters to carry at least the requested
        /// number of bits, which is why its entropy is computed from the sampling rather than from the byte
        /// count. Every other encoding is a faithful rendering of the bytes, so it carries eight bits per
        /// byte drawn.
        /// </remarks>
        internal static (string Value, double EntropyBits) Material(int bytes, SecretEncoding encoding)
        {
            if (encoding != SecretEncoding.Base62)
            {
                return (Encode(bytes, encoding), bytes * 8d);
            }

            var characters = CharactersFor(bytes, Base62.Length);

            return (Sample(Base62, characters), PasswordStrength.EntropyBits(characters, Base62.Length));
        }

        /// <summary>
        /// Encodes bytes as Base64 with the URL-safe alphabet and no padding, which is the form WebAuthn,
        /// VAPID and bearer tokens use.
        /// </summary>
        /// <param name="value">The bytes to encode.</param>
        internal static string ToBase64Url(ReadOnlySpan<byte> value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// Samples characters independently and uniformly from an alphabet.
        /// </summary>
        /// <param name="alphabet">The characters to choose from.</param>
        /// <param name="count">How many characters to choose.</param>
        internal static string Sample(string alphabet, int count)
        {
            var buffer = new char[count];
            RandomNumberGenerator.GetItems<char>(alphabet, buffer.AsSpan());

            var value = new string(buffer);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));

            return value;
        }

        /// <summary>
        /// How many characters from an alphabet are needed to carry at least a given number of random
        /// bytes, rounded up so the result is never weaker than what was asked for.
        /// </summary>
        /// <param name="bytes">Requested strength in bytes.</param>
        /// <param name="alphabetSize">Number of symbols in the alphabet.</param>
        internal static int CharactersFor(int bytes, int alphabetSize) =>
            (int)Math.Ceiling(bytes * 8d / Math.Log2(alphabetSize));

        /// <summary>Caller-facing description of an encoding, for the composition of a response.</summary>
        /// <param name="encoding">The encoding used.</param>
        internal static string Describe(SecretEncoding encoding) => encoding switch
        {
            SecretEncoding.Base64Url => "Base64url encoded",
            SecretEncoding.Base64 => "Base64 encoded",
            SecretEncoding.Hex => "hexadecimal",
            SecretEncoding.HexUpper => "uppercase hexadecimal",
            SecretEncoding.Base62 => "sampled from 62 digits and letters",
            _ => encoding.ToString()
        };

        /// <summary>
        /// Returns the characters one of the named alphabets contains.
        /// </summary>
        /// <param name="alphabet">A named alphabet — not <see cref="RandomStringAlphabet.Custom"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <see cref="RandomStringAlphabet.Custom"/> was asked for, which has no characters of its own.
        /// </exception>
        internal static string Alphabet(RandomStringAlphabet alphabet) => alphabet switch
        {
            RandomStringAlphabet.Alphanumeric => Base62,
            RandomStringAlphabet.Letters => PasswordCharsets.Uppercase + PasswordCharsets.Lowercase,
            RandomStringAlphabet.Lowercase => PasswordCharsets.Lowercase,
            RandomStringAlphabet.Uppercase => PasswordCharsets.Uppercase,
            RandomStringAlphabet.Digits => PasswordCharsets.Digits,
            RandomStringAlphabet.Hex => HexLower,
            RandomStringAlphabet.HexUpper => HexUpper,
            RandomStringAlphabet.Base64Url => Base64UrlAlphabet,
            _ => throw new ArgumentOutOfRangeException(
                nameof(alphabet), "A custom alphabet is supplied by the caller, not resolved by name.")
        };

        /// <summary>Caller-facing name of one of the named alphabets.</summary>
        /// <param name="alphabet">The alphabet used.</param>
        internal static string Describe(RandomStringAlphabet alphabet) => alphabet switch
        {
            RandomStringAlphabet.Alphanumeric => "digits and letters",
            RandomStringAlphabet.Letters => "letters",
            RandomStringAlphabet.Lowercase => "lowercase letters",
            RandomStringAlphabet.Uppercase => "uppercase letters",
            RandomStringAlphabet.Digits => "digits",
            RandomStringAlphabet.Hex => "hexadecimal digits",
            RandomStringAlphabet.HexUpper => "uppercase hexadecimal digits",
            RandomStringAlphabet.Base64Url => "the URL-safe Base64 alphabet",
            _ => "a supplied alphabet"
        };

        /// <summary>
        /// Returns the characters a backup code or recovery key format draws from.
        /// </summary>
        /// <param name="format">The format, already validated as one of the defined ones.</param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The format is not one of the defined ones. Callers validate first, so reaching this is a defect
        /// rather than a bad request.
        /// </exception>
        internal static string Alphabet(BackupCodeFormat format) => format switch
        {
            BackupCodeFormat.Alphanumeric => Crockford32,
            BackupCodeFormat.Numeric => PasswordCharsets.Digits,
            _ => throw new ArgumentOutOfRangeException(nameof(format), "The format is not a defined one.")
        };

        /// <summary>Caller-facing description of a backup code or recovery key format.</summary>
        /// <param name="format">The format used.</param>
        internal static string Describe(BackupCodeFormat format) => format switch
        {
            BackupCodeFormat.Alphanumeric =>
                "digits and uppercase letters, excluding I, L, O and U (32 character alphabet)",
            BackupCodeFormat.Numeric => "digits (10 character alphabet)",
            _ => format.ToString()
        };
    }
}
