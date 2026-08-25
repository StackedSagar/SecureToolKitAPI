using System.Text;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Base32 conversion using the standard RFC 4648 alphabet, which is the form authenticator
    /// applications expect a TOTP shared secret in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Base32 is an encoding, not encryption: it hides nothing and adds no strength. It is here because a
    /// TOTP secret has to be typed or scanned by a person, and 32 unambiguous uppercase symbols survive
    /// that better than Base64 does. A value encoded here is exactly as sensitive as the bytes behind it.
    /// </para>
    /// <para>
    /// .NET ships no Base32 API, so the transformation is written out here. That is a base conversion
    /// rather than a cryptographic primitive: no key, no randomness and no security property depends on
    /// it, and every RFC 4648 test vector is asserted in the unit tests.
    /// </para>
    /// <para>
    /// Decoding is deliberately forgiving about presentation and strict about content. Whitespace and the
    /// hyphens people insert to make a secret readable are ignored, and lowercase input is accepted,
    /// because all three are how a secret arrives when it has been copied out of an authenticator or a
    /// printout. A symbol outside the alphabet, or a symbol after padding has begun, is rejected.
    /// </para>
    /// </remarks>
    internal static class Base32Text
    {
        /// <summary>
        /// The RFC 4648 §6 alphabet: the 26 uppercase letters followed by the digits 2 to 7. The digits
        /// that look like letters — 0, 1 and 8 — are absent by design.
        /// </summary>
        internal const string Rfc4648Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <summary>Bits carried by one Base32 symbol.</summary>
        private const int BitsPerSymbol = 5;

        /// <summary>Symbols in a whole Base32 block, which encodes five bytes.</summary>
        private const int SymbolsPerBlock = 8;

        /// <summary>Bytes encoded by one whole block of <see cref="SymbolsPerBlock"/> symbols.</summary>
        private const int BytesPerBlock = 5;

        /// <summary>
        /// Encodes bytes as Base32.
        /// </summary>
        /// <param name="value">The bytes to encode. An empty input produces an empty string.</param>
        /// <param name="padding">
        /// <c>true</c> to pad the result to a whole block with <c>=</c>, as RFC 4648 requires;
        /// <c>false</c> to leave it unpadded, which is what an <c>otpauth</c> URI uses.
        /// </param>
        /// <returns>The encoded text, in uppercase.</returns>
        internal static string Encode(ReadOnlySpan<byte> value, bool padding = true)
        {
            if (value.IsEmpty)
            {
                return string.Empty;
            }

            var blocks = (value.Length + BytesPerBlock - 1) / BytesPerBlock;
            var builder = new StringBuilder(blocks * SymbolsPerBlock);

            // Bits are drained out of the accumulator five at a time as bytes are shifted in. The
            // accumulator is masked back down after each drain: without that, the left shifts overflow a
            // 32-bit integer once five bytes have been read.
            var buffered = 0;
            var bits = 0;

            foreach (var current in value)
            {
                buffered = (buffered << 8) | current;
                bits += 8;

                while (bits >= BitsPerSymbol)
                {
                    builder.Append(Rfc4648Alphabet[(buffered >> (bits - BitsPerSymbol)) & 31]);
                    bits -= BitsPerSymbol;
                }

                buffered &= (1 << bits) - 1;
            }

            // A trailing partial symbol is padded on the right with zero bits, per RFC 4648.
            if (bits > 0)
            {
                builder.Append(Rfc4648Alphabet[(buffered << (BitsPerSymbol - bits)) & 31]);
            }

            if (padding)
            {
                while (builder.Length % SymbolsPerBlock != 0)
                {
                    builder.Append('=');
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Attempts to decode Base32 text, without throwing and without reporting which character was at
        /// fault.
        /// </summary>
        /// <param name="value">
        /// The text to decode. Whitespace and hyphens are ignored, lowercase is accepted, and trailing
        /// <c>=</c> padding is optional.
        /// </param>
        /// <param name="decoded">The decoded bytes, or an empty array when the text is not valid Base32.</param>
        /// <returns><c>true</c> when the text was decoded.</returns>
        /// <remarks>
        /// <para>
        /// Failure is a return value rather than an exception because the input is usually something a
        /// person typed: the caller turns it into a bad request with a message of its own, and nothing
        /// about the supplied value is echoed from here.
        /// </para>
        /// <para>
        /// A final partial block of one, three or six symbols is rejected: no whole number of bytes
        /// encodes to those lengths, so the input is truncated. Non-zero leftover bits in an otherwise
        /// well-formed final block are accepted and discarded, which is the lenient reading of RFC 4648 —
        /// several authenticators emit them, and rejecting a secret that every other tool accepts would be
        /// the worse failure.
        /// </para>
        /// </remarks>
        internal static bool TryDecode(string? value, out byte[] decoded)
        {
            decoded = [];

            if (value is null)
            {
                return false;
            }

            // Validated and counted first, so the output array is allocated at exactly the right size and
            // no partly-filled buffer of secret material has to be copied or discarded afterwards.
            if (!TryCountSymbols(value, out var symbols))
            {
                return false;
            }

            var bytes = new byte[symbols * BitsPerSymbol / 8];
            var buffered = 0;
            var bits = 0;
            var written = 0;

            foreach (var character in value)
            {
                if (character == '=')
                {
                    // Padding only ever appears at the end; anything after it was already rejected.
                    break;
                }

                if (IsIgnorable(character))
                {
                    continue;
                }

                buffered = (buffered << BitsPerSymbol) | IndexOf(character);
                bits += BitsPerSymbol;

                if (bits >= 8)
                {
                    bytes[written++] = (byte)((buffered >> (bits - 8)) & 0xFF);
                    bits -= 8;
                }

                buffered &= (1 << bits) - 1;
            }

            decoded = bytes;

            return true;
        }

        /// <summary>
        /// Validates the text and counts the symbols it contains, so the decoded size is known before any
        /// buffer is allocated.
        /// </summary>
        /// <param name="value">The text to inspect.</param>
        /// <param name="symbols">Number of alphabet symbols found.</param>
        /// <returns><c>false</c> when the text contains an unusable character or an impossible length.</returns>
        private static bool TryCountSymbols(string value, out int symbols)
        {
            symbols = 0;
            var padded = false;

            foreach (var character in value)
            {
                if (character == '=')
                {
                    padded = true;

                    continue;
                }

                if (IsIgnorable(character))
                {
                    continue;
                }

                // A symbol after padding has begun means the value was concatenated or corrupted, and
                // treating it as data would silently accept something no encoder produces.
                if (padded)
                {
                    return false;
                }

                if (IndexOf(character) < 0)
                {
                    return false;
                }

                symbols++;
            }

            // 1, 3 and 6 are the symbol counts no whole number of bytes can produce: five bytes need 8
            // symbols, and the shorter blocks need 2, 4, 5 or 7.
            return symbols % SymbolsPerBlock is not (1 or 3 or 6);
        }

        /// <summary>
        /// Reports whether a character is presentation rather than content: whitespace, or a hyphen used to
        /// group a secret so it can be read back accurately.
        /// </summary>
        /// <param name="character">The character to test.</param>
        private static bool IsIgnorable(char character) => char.IsWhiteSpace(character) || character == '-';

        /// <summary>
        /// Resolves a character to its value in the alphabet, accepting lowercase.
        /// </summary>
        /// <param name="character">The character to resolve.</param>
        /// <returns>The value, or a negative number when the character is not in the alphabet.</returns>
        private static int IndexOf(char character) =>
            Rfc4648Alphabet.IndexOf(char.ToUpperInvariant(character));
    }
}
