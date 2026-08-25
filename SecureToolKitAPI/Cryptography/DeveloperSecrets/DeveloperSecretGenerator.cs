using System.Globalization;
using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.DeveloperSecrets
{
    /// <summary>
    /// Generates the secrets a developer wires into a service: API keys, JWT signing secrets, opaque OAuth
    /// values, the random values a WebAuthn registration needs, random strings and Web Push VAPID keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every value comes from <see cref="RandomNumberGenerator"/>, either as raw bytes that are then
    /// rendered as text or by sampling an alphabet, so the reported entropy is the real entropy of the
    /// process. No value is derived from another, and no value is retained after it is returned.
    /// </para>
    /// <para>
    /// The class is stateless and therefore safe to share as a singleton. Raw byte buffers are cleared once
    /// the text form has been built; the returned strings are immutable and can only be discarded by the
    /// caller.
    /// </para>
    /// <para>
    /// The advisory threshold here is 128 bits rather than the 60 used for human passwords. These are
    /// machine credentials: nothing rate-limits an attacker who has the ciphertext or the token endpoint,
    /// so they are held to the standard expected of a cryptographic key.
    /// </para>
    /// </remarks>
    public sealed class DeveloperSecretGenerator : IDeveloperSecretGenerator
    {
        /// <summary>
        /// Entropy below which a machine credential should not be relied on, used to decide whether to
        /// attach an advisory.
        /// </summary>
        private const double MachineCredentialThresholdBits = 128d;

        /// <summary>The only curve RFC 8292 allows for VAPID, in bits.</summary>
        private const int VapidCurveSizeBits = 256;

        /// <summary>Size of each P-256 coordinate and of the private scalar, in bytes.</summary>
        private const int VapidCoordinateBytes = 32;

        /// <inheritdoc />
        public GeneratedSecret GenerateApiKey(ByteSecretSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var (random, entropyBits) = Material(spec.Bytes, spec.Encoding);

            // The prefix is not secret and adds no entropy: it exists so a leaked key can be recognised by
            // a secret scanner, and so support can tell one environment's keys from another's.
            return Describe(
                spec.Prefix + random,
                entropyBits,
                Composition(spec.Bytes, spec.Encoding, random.Length, spec.Prefix.Length));
        }

        /// <inheritdoc />
        public GeneratedSecret GenerateJwtSecret(JwtSecretSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var (value, entropyBits) = Material(spec.KeySizeBytes, spec.Encoding);
            var bits = spec.KeySizeBytes * 8;

            return Describe(
                value,
                entropyBits,
                $"{bits}-bit HMAC key, {SecretText.Describe(spec.Encoding)} ({value.Length} characters)",
                spec.Algorithm.ToString(),
                [
                    "An HMAC secret is symmetric: whoever can verify a token can also mint one. When tokens "
                    + "are verified by a party that must not be able to issue them, sign with an asymmetric "
                    + "algorithm such as RS256 or ES256 instead.",
                    "Keep this secret on the server, in a secrets manager or an environment variable. Never "
                    + "commit it, never send it to a browser or mobile client, and never put it in a token "
                    + "payload — a JWT payload is only Base64url encoded, not encrypted."
                ]);
        }

        /// <inheritdoc />
        public GeneratedSecret GenerateOAuthToken(OAuthTokenSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var bytes = spec.ResolvedBytes;
            var (value, entropyBits) = Material(bytes, spec.Encoding);

            var advisories = new List<string>
            {
                AdviceFor(spec.Kind),
                "If this value is stored server-side, store a hash of it rather than the value itself, so a "
                + "leaked database does not hand over working credentials."
            };

            return Describe(
                value,
                entropyBits,
                Composition(bytes, spec.Encoding, value.Length, prefixLength: 0),
                spec.Kind.ToString(),
                advisories);
        }

        /// <inheritdoc />
        public GeneratedWebAuthnCredential GenerateWebAuthnCredential(WebAuthnSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            return new GeneratedWebAuthnCredential
            {
                Challenge = RandomBase64Url(spec.ChallengeBytes),
                UserHandle = RandomBase64Url(spec.UserHandleBytes),
                ChallengeBytes = spec.ChallengeBytes,
                UserHandleBytes = spec.UserHandleBytes,
                Format = "Base64url encoded without padding, as the WebAuthn JSON API expects.",
                Warnings =
                [
                    "The challenge must be remembered server-side, tied to the ceremony it was issued for, "
                    + "used once and then discarded. Accepting a challenge the server did not issue defeats "
                    + "the point of WebAuthn.",
                    "The credential ID and the credential public key are produced by the authenticator during "
                    + "registration. They cannot be generated on a server — store the ones the browser "
                    + "returns.",
                    "A user handle must carry no personal information, which is why it is random. Store it "
                    + "against the account and reuse it for that account's later ceremonies."
                ]
            };
        }

        /// <inheritdoc />
        public GeneratedSecret GenerateRandomString(RandomStringSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var alphabet = spec.Characters();
            var value = SecretText.Sample(alphabet, spec.Length);

            var description = spec.Alphabet == RandomStringAlphabet.Custom
                ? "a supplied alphabet"
                : SecretText.Describe(spec.Alphabet);

            return Describe(
                value,
                PasswordStrength.EntropyBits(spec.Length, alphabet.Length),
                $"{spec.Length} characters sampled from {description} ({alphabet.Length} symbols)");
        }

        /// <inheritdoc />
        public GeneratedVapidKey GenerateVapidKey()
        {
            using var ecdsa = ECDsa.Create(EcCurves.FromKeySize(VapidCurveSizeBits));

            var parameters = ecdsa.ExportParameters(includePrivateParameters: true);
            byte[]? scalar = null;

            try
            {
                var point = UncompressedPoint(parameters.Q);
                scalar = Coordinate(parameters.D);

                return new GeneratedVapidKey
                {
                    PublicKey = SecretText.ToBase64Url(point),
                    PrivateKey = SecretText.ToBase64Url(scalar),
                    PublicKeyPem = ecdsa.ExportSubjectPublicKeyInfoPem(),
                    PrivateKeyPem = ecdsa.ExportPkcs8PrivateKeyPem(),
                    Curve = "P-256",
                    Format =
                        "Base64url encoded without padding: the public key is the 65 byte uncompressed point "
                        + "(0x04 followed by X and Y) and the private key is the 32 byte scalar.",
                    Warnings =
                    [
                        "The private key must stay on the application server. The public key is published to "
                        + "browsers as the application server key and is not secret.",
                        "Rotating this pair invalidates every existing push subscription, because a "
                        + "subscription is bound to the public key it was created with. Keep one pair for the "
                        + "lifetime of the deployment.",
                        "VAPID also needs a contact subject — a mailto: or https: URI that identifies you to "
                        + "the push service. That is configuration rather than a secret, so it is not "
                        + "generated here."
                    ]
                };
            }
            finally
            {
                // The private scalar exists in two buffers by this point: the one the export handed back
                // and the fixed-width copy. Both are cleared; the public coordinates need no clearing.
                CryptographicOperations.ZeroMemory(scalar);
                CryptographicOperations.ZeroMemory(parameters.D);
            }
        }

        /// <summary>
        /// Draws the requested amount of randomness and renders it, returning the text together with the
        /// entropy it carries.
        /// </summary>
        /// <param name="bytes">Requested strength in bytes.</param>
        /// <param name="encoding">How the value is rendered.</param>
        /// <remarks>
        /// Base62 cannot be produced by re-basing raw bytes without bias, so it is sampled character by
        /// character instead — enough characters to carry at least the requested number of bits, which is
        /// why its entropy is computed from the sampling rather than from the byte count. The rule lives in
        /// <see cref="SecretText"/> so every endpoint that offers an encoding applies the same one.
        /// </remarks>
        private static (string Value, double EntropyBits) Material(int bytes, SecretEncoding encoding) =>
            SecretText.Material(bytes, encoding);

        /// <summary>Draws random bytes and returns them Base64url encoded.</summary>
        /// <param name="bytes">How many random bytes to draw.</param>
        private static string RandomBase64Url(int bytes) =>
            SecretText.Encode(bytes, SecretEncoding.Base64Url);

        /// <summary>
        /// Describes how a value was built, without revealing any part of it.
        /// </summary>
        /// <param name="bytes">Requested strength in bytes.</param>
        /// <param name="encoding">How the value was rendered.</param>
        /// <param name="characters">Number of characters in the random part.</param>
        /// <param name="prefixLength">Number of characters in the prefix, if any.</param>
        /// <remarks>
        /// Only the length of the prefix is reported, never the prefix itself: a caller could put anything
        /// in it, and this description is meant to be safe to show and to log.
        /// </remarks>
        private static string Composition(int bytes, SecretEncoding encoding, int characters, int prefixLength)
        {
            var composition =
                $"{bytes * 8} random bits, {SecretText.Describe(encoding)} ({characters} characters)";

            return prefixLength > 0
                ? $"{composition}, behind a {prefixLength} character prefix"
                : composition;
        }

        /// <summary>How a particular kind of OAuth value has to be handled.</summary>
        /// <param name="kind">The kind of value generated.</param>
        private static string AdviceFor(OAuthTokenKind kind) => kind switch
        {
            OAuthTokenKind.RefreshToken =>
                "A refresh token is long lived and can be exchanged for new access tokens, so store only a "
                + "hash of it, rotate it on every use, and revoke the whole family if a rotated token is "
                + "replayed.",
            OAuthTokenKind.ClientSecret =>
                "A client secret belongs only to a confidential client running on a server. Never ship one "
                + "in a browser, mobile or desktop application — a public client should use PKCE instead.",
            OAuthTokenKind.AuthorizationCode =>
                "An authorization code must be single use, expire within about a minute, and be bound to the "
                + "client and redirect URI it was issued for. Require PKCE so an intercepted code is useless.",
            _ =>
                "An access token is a bearer credential: whoever holds it can use it. Keep its lifetime "
                + "short, and never place it in a URL, a page or a log line."
        };

        /// <summary>
        /// Wraps a generated value with the figures that describe it, and attaches the standard advisory
        /// when it carries less entropy than a machine credential should.
        /// </summary>
        /// <param name="value">The generated value.</param>
        /// <param name="entropyBits">Entropy of the generation process, before rounding.</param>
        /// <param name="composition">Description of how the value was built.</param>
        /// <param name="kind">The specific shape that was asked for, when the endpoint has one.</param>
        /// <param name="warnings">Advisories specific to this kind of secret.</param>
        /// <remarks>
        /// The strength label is derived from the rounded figure that is reported, so a response can never
        /// show a number and a label that disagree.
        /// </remarks>
        private static GeneratedSecret Describe(
            string value,
            double entropyBits,
            string composition,
            string? kind = null,
            IReadOnlyList<string>? warnings = null)
        {
            var rounded = PasswordStrength.Round(entropyBits);
            var advisories = new List<string>();

            if (warnings is not null)
            {
                advisories.AddRange(warnings);
            }

            if (rounded < MachineCredentialThresholdBits)
            {
                var bits = rounded.ToString("0.#", CultureInfo.InvariantCulture);
                var threshold = MachineCredentialThresholdBits.ToString("0", CultureInfo.InvariantCulture);

                advisories.Add(
                    $"About {bits} bits of entropy, which is below the {threshold} bits expected of a "
                    + "machine credential such as a key or a token. Ask for more bytes, a longer string, or "
                    + "a larger alphabet.");
            }

            return new GeneratedSecret
            {
                Value = value,
                Length = value.Length,
                EntropyBits = rounded,
                Strength = PasswordStrength.Describe(rounded),
                Composition = composition,
                Kind = kind,
                Warnings = advisories
            };
        }

        /// <summary>
        /// Builds the uncompressed public point, <c>0x04 || X || Y</c>, which is the form a browser is
        /// given as the <c>applicationServerKey</c> and the form Web Push libraries expect.
        /// </summary>
        /// <param name="point">The public point as exported by .NET.</param>
        /// <remarks>The coordinates of a public key are not secret, so nothing here needs clearing.</remarks>
        private static byte[] UncompressedPoint(ECPoint point)
        {
            var x = Coordinate(point.X);
            var y = Coordinate(point.Y);

            var uncompressed = new byte[1 + x.Length + y.Length];
            uncompressed[0] = 0x04;
            x.CopyTo(uncompressed.AsSpan(1));
            y.CopyTo(uncompressed.AsSpan(1 + x.Length));

            return uncompressed;
        }

        /// <summary>
        /// Normalises an exported elliptic-curve value to the fixed width VAPID expects.
        /// </summary>
        /// <param name="value">A coordinate or scalar as exported by .NET.</param>
        /// <returns>
        /// A fresh 32-byte big-endian buffer, left-padded with zeros if the export was shorter.
        /// </returns>
        /// <exception cref="CryptographicException">The platform returned no value at all.</exception>
        /// <remarks>
        /// .NET already returns field-width values for a named curve, so this only guards against a value
        /// that is shorter or that carries a leading sign byte. Getting the width wrong would produce a key
        /// that every Web Push client rejects, which is worth a few lines to rule out. A missing value
        /// would be a platform defect rather than a bad request, so it surfaces as a bare 500 rather than
        /// as advice to the caller.
        /// </remarks>
        private static byte[] Coordinate(byte[]? value)
        {
            if (value is null || value.Length == 0)
            {
                throw new CryptographicException("The generated key could not be exported.");
            }

            var padded = new byte[VapidCoordinateBytes];

            var source = value.Length > VapidCoordinateBytes
                ? value.AsSpan(value.Length - VapidCoordinateBytes)
                : value.AsSpan();

            source.CopyTo(padded.AsSpan(VapidCoordinateBytes - source.Length));

            return padded;
        }
    }
}
