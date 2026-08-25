using System.Security.Cryptography;
using System.Text;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Writes the OpenSSH public key encoding defined by RFC 4253 and RFC 5656: the length-prefixed binary
    /// blob that sits inside an <c>authorized_keys</c> line, and the <c>SHA256:</c> fingerprint OpenSSH
    /// prints for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is serialization, not cryptography. Nothing here generates, derives or transforms key material:
    /// the caller generates a key with the platform's own <see cref="RSA"/> or <see cref="ECDsa"/>
    /// implementation and passes the public parameters in, and this class arranges them in the byte order
    /// OpenSSH expects. The distinction matters because writing a wire format by hand is ordinary work,
    /// while writing a cryptographic primitive by hand is not.
    /// </para>
    /// <para>
    /// Two encodings appear in the format. A <c>string</c> is a four-byte big-endian length followed by that
    /// many bytes. An <c>mpint</c> is a signed big-endian integer in the same envelope, carrying no leading
    /// zero bytes except the single one needed to keep a value positive when its top bit is set — which is
    /// always the case for an RSA modulus, so an RSA modulus is always one byte longer than the key size
    /// suggests.
    /// </para>
    /// </remarks>
    internal static class SshWireFormat
    {
        /// <summary>The prefix OpenSSH puts in front of a Base64 SHA-256 fingerprint.</summary>
        private const string FingerprintPrefix = "SHA256:";

        /// <summary>The key type name that identifies an SSH RSA key.</summary>
        internal const string RsaKeyType = "ssh-rsa";

        /// <summary>Builds the public key blob for an RSA key.</summary>
        /// <param name="parameters">Public RSA parameters, exported without the private key.</param>
        /// <returns>The blob, ready to be Base64 encoded into an <c>authorized_keys</c> line.</returns>
        /// <remarks>
        /// The exponent comes first and the modulus second, both as <c>mpint</c>, which is the order in
        /// RFC 4253 and the reverse of how the two are usually written.
        /// </remarks>
        internal static byte[] RsaPublicKeyBlob(RSAParameters parameters)
        {
            var buffer = new List<byte>(600);

            WriteString(buffer, RsaKeyType);
            WriteMpInt(buffer, Required(parameters.Exponent, "exponent"));
            WriteMpInt(buffer, Required(parameters.Modulus, "modulus"));

            return [.. buffer];
        }

        /// <summary>Builds the public key blob for an ECDSA key on a NIST curve.</summary>
        /// <param name="curveName">The SSH spelling of the curve, for example <c>nistp256</c>.</param>
        /// <param name="point">The public point, exported without the private key.</param>
        /// <returns>The blob, ready to be Base64 encoded into an <c>authorized_keys</c> line.</returns>
        /// <remarks>
        /// The curve name appears twice — once inside the key type and once on its own — because RFC 5656
        /// defines one key type per curve and still carries the identifier separately. The point is the
        /// uncompressed SEC 1 form: a <c>0x04</c> marker followed by the two coordinates, each already
        /// padded to the curve's field size by the platform.
        /// </remarks>
        internal static byte[] EcdsaPublicKeyBlob(string curveName, ECPoint point)
        {
            var x = Required(point.X, "public point");
            var y = Required(point.Y, "public point");

            var encodedPoint = new byte[1 + x.Length + y.Length];
            encodedPoint[0] = 0x04;
            x.CopyTo(encodedPoint, 1);
            y.CopyTo(encodedPoint, 1 + x.Length);

            var buffer = new List<byte>(200);

            WriteString(buffer, EcdsaKeyType(curveName));
            WriteString(buffer, curveName);
            WriteBlock(buffer, encodedPoint);

            return [.. buffer];
        }

        /// <summary>The key type name for an ECDSA key on the given curve.</summary>
        /// <param name="curveName">The SSH spelling of the curve, for example <c>nistp256</c>.</param>
        internal static string EcdsaKeyType(string curveName) => $"ecdsa-sha2-{curveName}";

        /// <summary>
        /// Formats a public key the way it appears in <c>authorized_keys</c>: the key type, the Base64 blob
        /// and an optional comment, separated by single spaces.
        /// </summary>
        /// <param name="keyType">The key type name, for example <c>ssh-rsa</c>.</param>
        /// <param name="blob">The public key blob.</param>
        /// <param name="comment">The trailing comment, or <c>null</c> for a line without one.</param>
        /// <remarks>
        /// The comment is whatever the caller asked for and is validated before it reaches here, because a
        /// line break in it would turn one authorized key into two.
        /// </remarks>
        internal static string AuthorizedKeysLine(string keyType, byte[] blob, string? comment)
        {
            var line = $"{keyType} {Base64Text.Encode(blob)}";

            return string.IsNullOrEmpty(comment) ? line : $"{line} {comment}";
        }

        /// <summary>
        /// The fingerprint OpenSSH prints for a public key: the SHA-256 of the blob, Base64 encoded with
        /// the padding removed, behind a <c>SHA256:</c> prefix.
        /// </summary>
        /// <param name="blob">The public key blob.</param>
        /// <remarks>
        /// This is a hash of a public value, so it is safe to log and to compare in the open. It is the
        /// string <c>ssh-keygen -lf</c> reports, which is what makes it useful for confirming that the key
        /// on the server is the key that was generated here.
        /// </remarks>
        internal static string Fingerprint(byte[] blob) =>
            FingerprintPrefix + Base64Text.Encode(SHA256.HashData(blob)).TrimEnd('=');

        /// <summary>Writes an ASCII name as a length-prefixed string.</summary>
        private static void WriteString(List<byte> buffer, string value) =>
            WriteBlock(buffer, Encoding.ASCII.GetBytes(value));

        /// <summary>Writes a length-prefixed block: four bytes of big-endian length, then the bytes.</summary>
        private static void WriteBlock(List<byte> buffer, byte[] value)
        {
            buffer.Add((byte)(value.Length >> 24));
            buffer.Add((byte)(value.Length >> 16));
            buffer.Add((byte)(value.Length >> 8));
            buffer.Add((byte)value.Length);
            buffer.AddRange(value);
        }

        /// <summary>
        /// Writes a big-endian integer as an <c>mpint</c>: leading zero bytes removed, and one zero byte
        /// added back when the top bit would otherwise make the value read as negative.
        /// </summary>
        private static void WriteMpInt(List<byte> buffer, byte[] value)
        {
            var start = 0;

            while (start < value.Length && value[start] == 0)
            {
                start++;
            }

            var trimmed = value[start..];

            if (trimmed.Length == 0)
            {
                // Zero is the empty string in this encoding, not a single zero byte.
                WriteBlock(buffer, []);
                return;
            }

            if ((trimmed[0] & 0x80) == 0)
            {
                WriteBlock(buffer, trimmed);
                return;
            }

            var positive = new byte[trimmed.Length + 1];
            trimmed.CopyTo(positive, 1);

            WriteBlock(buffer, positive);
        }

        /// <summary>
        /// Returns a component of an exported key, or fails loudly when the platform did not provide one.
        /// </summary>
        /// <remarks>
        /// A freshly generated key always has these components, so a missing one is a defect in this API
        /// rather than anything the caller did. It is deliberately not a
        /// <see cref="Abstractions.CryptographicRequestException"/>: that type means "the request was
        /// wrong" and would be answered with a 400, which would be a lie here.
        /// </remarks>
        private static byte[] Required(byte[]? value, string component) =>
            value ?? throw new InvalidOperationException(
                $"The generated key did not expose its {component}, so no SSH public key could be written.");
    }
}
