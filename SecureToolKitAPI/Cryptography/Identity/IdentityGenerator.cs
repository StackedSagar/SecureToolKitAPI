using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Identity
{
    /// <summary>
    /// Generates identity and second-factor values: UUIDs, TOTP shared secrets, authenticator enrollments,
    /// the code a secret currently produces, and Base32 rendering.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every random byte comes from <see cref="RandomNumberGenerator"/>. The HMAC behind a TOTP comes from
    /// the .NET implementations; the only thing computed here is the RFC 4226 truncation that turns a MAC
    /// into digits, which is decimal arithmetic rather than a cryptographic primitive and is asserted
    /// against the published RFC 6238 vectors in the tests.
    /// </para>
    /// <para>
    /// A TOTP secret is a complete second factor. Nothing here logs a secret, an enrollment URI or a
    /// caller-supplied secret, and every decoded key and MAC buffer is wiped with
    /// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> once it has been used.
    /// </para>
    /// <para>
    /// The generator holds no state and only calls thread-safe APIs, which is why it is registered as a
    /// singleton.
    /// </para>
    /// </remarks>
    public sealed class IdentityGenerator : IIdentityGenerator
    {
        /// <summary>Bytes in a UUID.</summary>
        private const int UuidBytes = 16;

        /// <summary>Bytes of the version 7 layout given over to the millisecond timestamp.</summary>
        private const int TimestampBytes = 6;

        /// <inheritdoc />
        public GeneratedUuids GenerateUuids(UuidSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var values = new string[spec.Count];

            for (var index = 0; index < values.Length; index++)
            {
                values[index] = Format(Compose(spec.Version), spec.Format, spec.Uppercase);
            }

            return new GeneratedUuids
            {
                Values = values,
                Version = spec.Version == UuidVersion.V7 ? "v7" : "v4",
                Format = Describe(spec.Format),
                RandomBits = spec.RandomBits,
                Composition = spec.Describe(),
                Warnings = UuidAdvice(spec)
            };
        }

        /// <inheritdoc />
        public GeneratedTotpSecret GenerateTotpSecret(TotpSecretSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var bytes = spec.ResolvedBytes;
            var parameters = spec.Parameters;
            var entropyBits = bytes * 8d;

            return new GeneratedTotpSecret
            {
                Secret = NewSecret(bytes),
                Bytes = bytes,
                EntropyBits = entropyBits,
                Strength = PasswordStrength.Describe(entropyBits),
                Algorithm = parameters.AlgorithmName,
                Digits = parameters.Digits,
                PeriodSeconds = parameters.PeriodSeconds,
                Composition =
                    $"{bytes * 8} random bits, Base32 encoded for {parameters.Describe()}",
                Warnings = TotpSecretAdvice(parameters, bytes)
            };
        }

        /// <inheritdoc />
        public TotpEnrollment CreateTotpEnrollment(TotpEnrollmentSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var parameters = spec.Parameters;
            string secret;
            int bytes;

            if (spec.Secret is null)
            {
                bytes = new TotpSecretSpec { Bytes = spec.Bytes, Parameters = parameters }.ResolvedBytes;
                secret = NewSecret(bytes);
            }
            else
            {
                // A supplied secret is normalised through a decode and re-encode, so the URI carries the
                // canonical unpadded form however the caller wrote it.
                (secret, bytes) = Normalise(spec.Secret);
            }

            var issuer = spec.Issuer.Trim();
            var account = spec.Account.Trim();

            return new TotpEnrollment
            {
                Secret = secret,
                Uri = EnrollmentUri(issuer, account, secret, parameters),
                Issuer = issuer,
                Account = account,
                Algorithm = parameters.AlgorithmName,
                Digits = parameters.Digits,
                PeriodSeconds = parameters.PeriodSeconds,
                Bytes = bytes,
                Composition = $"otpauth URI for {parameters.Describe()}",
                Warnings = EnrollmentAdvice(parameters)
            };
        }

        /// <inheritdoc />
        public TotpCode ComputeTotpCode(TotpCodeSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var parameters = spec.Parameters;
            var seconds = spec.UnixTimeSeconds ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Validation has already proved the secret decodes, so this cannot fail; the result is checked
            // anyway rather than assumed, because silently computing a code from an empty key would be the
            // worst possible failure here.
            if (!Base32Text.TryDecode(spec.Secret, out var key) || key.Length == 0)
            {
                throw new CryptographicRequestException("The secret is not valid Base32.");
            }

            var counter = seconds / parameters.PeriodSeconds;

            try
            {
                return new TotpCode
                {
                    Code = Truncate(Mac(key, counter, parameters.Algorithm), parameters),
                    UnixTimeSeconds = seconds,
                    Counter = counter,
                    ValidForSeconds = parameters.PeriodSeconds - (int)(seconds % parameters.PeriodSeconds),
                    Algorithm = parameters.AlgorithmName,
                    Digits = parameters.Digits,
                    PeriodSeconds = parameters.PeriodSeconds,
                    Composition =
                        $"RFC 6238 code for counter {counter} using {parameters.Describe()}",
                    Warnings = CodeAdvice()
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <inheritdoc />
        public EncodedText EncodeBase32(Base32Spec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);

            // Decoding the input is the validation, so it happens once rather than twice.
            var input = spec.Decode();
            var encoded = Base32Text.Encode(input, spec.Padding);

            if (spec.Lowercase)
            {
                encoded = encoded.ToLowerInvariant();
            }

            var padding = spec.Padding ? "padded" : "unpadded";
            var casing = spec.Lowercase ? "lowercase" : "uppercase";

            return new EncodedText
            {
                Value = encoded,
                Encoding = "Base32 (RFC 4648)",
                Bytes = input.Length,
                Length = encoded.Length,
                Composition = $"{input.Length} bytes as {padding}, {casing} Base32",
                Warnings =
                [
                    "Base32 is an encoding, not encryption. It is reversible by anyone and protects "
                    + "nothing: the result is exactly as sensitive as the input it came from.",
                    "Authenticator applications ignore case and padding in a TOTP secret, so a value "
                    + "written either way enrolls the same."
                ]
            };
        }

        /// <summary>
        /// Draws a new TOTP secret and renders it in the unpadded Base32 an <c>otpauth</c> URI uses.
        /// </summary>
        /// <param name="bytes">Bytes of randomness to draw.</param>
        /// <remarks>The raw key is wiped as soon as it has been encoded.</remarks>
        private static string NewSecret(int bytes)
        {
            var key = RandomNumberGenerator.GetBytes(bytes);

            try
            {
                return Base32Text.Encode(key, padding: false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>
        /// Re-encodes a caller-supplied secret into the canonical unpadded uppercase form, so the grouping
        /// or case they wrote it in does not travel into the URI.
        /// </summary>
        /// <param name="secret">The supplied Base32 secret, already validated.</param>
        /// <returns>The canonical form and how many bytes it decodes to.</returns>
        /// <exception cref="CryptographicRequestException">The secret is not valid Base32.</exception>
        private static (string Secret, int Bytes) Normalise(string secret)
        {
            // Validation has already proved this decodes; it is checked rather than assumed, because
            // building an enrollment around an empty key would be the worst possible failure here.
            if (!Base32Text.TryDecode(secret, out var key))
            {
                throw new CryptographicRequestException("The secret is not valid Base32.");
            }

            try
            {
                return (Base32Text.Encode(key, padding: false), key.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>
        /// Builds the 16 bytes of a UUID: random material with the RFC 9562 version and variant markers
        /// written into it, and for version 7 a millisecond timestamp in front.
        /// </summary>
        /// <param name="version">Which layout to build.</param>
        /// <remarks>
        /// The fields are placed by hand rather than left to a framework helper, so the layout is explicit
        /// and the tests can assert the version and variant nibbles directly. The randomness still comes
        /// from <see cref="RandomNumberGenerator"/>.
        /// </remarks>
        private static byte[] Compose(UuidVersion version)
        {
            var value = RandomNumberGenerator.GetBytes(UuidBytes);

            if (version == UuidVersion.V7)
            {
                // A 48-bit big-endian count of milliseconds since the Unix epoch occupies the first six
                // bytes, which is what makes these values sort in the order they were created.
                Span<byte> milliseconds = stackalloc byte[8];
                BinaryPrimitives.WriteInt64BigEndian(
                    milliseconds,
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

                milliseconds[^TimestampBytes..].CopyTo(value);
            }

            // The version goes in the high nibble of byte 6, and the variant in the top two bits of byte 8.
            // Both overwrite random bits, which is why a version 4 value carries 122 and not 128.
            value[6] = (byte)((value[6] & 0x0F) | (version == UuidVersion.V7 ? 0x70 : 0x40));
            value[8] = (byte)((value[8] & 0x3F) | 0x80);

            return value;
        }

        /// <summary>Writes UUID bytes in the requested form.</summary>
        /// <param name="value">The 16 bytes to write.</param>
        /// <param name="format">Which form to write.</param>
        /// <param name="uppercase">Writes the hexadecimal digits in uppercase.</param>
        private static string Format(byte[] value, UuidFormat format, bool uppercase)
        {
            var hex = Convert.ToHexString(value);

            if (!uppercase)
            {
                hex = hex.ToLowerInvariant();
            }

            if (format == UuidFormat.Compact)
            {
                return hex;
            }

            var canonical =
                $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";

            return format switch
            {
                UuidFormat.Braced => $"{{{canonical}}}",
                UuidFormat.Urn => $"urn:uuid:{canonical}",
                _ => canonical
            };
        }

        /// <summary>Names a UUID format for the response.</summary>
        /// <param name="format">The format used.</param>
        private static string Describe(UuidFormat format) => format switch
        {
            UuidFormat.Compact => "compact",
            UuidFormat.Braced => "braced",
            UuidFormat.Urn => "urn",
            _ => "hyphenated"
        };

        /// <summary>
        /// Builds the <c>otpauth</c> URI an authenticator reads, with the issuer repeated in the label and
        /// in a parameter as the de facto format requires.
        /// </summary>
        /// <param name="issuer">The service name.</param>
        /// <param name="account">The account name.</param>
        /// <param name="secret">The Base32 secret.</param>
        /// <param name="parameters">The parameters both sides must agree on.</param>
        /// <remarks>
        /// Every component is percent-encoded, so a label containing a space or an ampersand cannot change
        /// how the URI parses. The algorithm and digits are always written out: an authenticator that
        /// assumed SHA-1 and six digits would silently produce codes the server rejects.
        /// </remarks>
        private static string EnrollmentUri(
            string issuer,
            string account,
            string secret,
            TotpParameters parameters)
        {
            var label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}";

            return $"otpauth://totp/{label}"
                + $"?secret={secret}"
                + $"&issuer={Uri.EscapeDataString(issuer)}"
                + $"&algorithm={parameters.AlgorithmName}"
                + $"&digits={parameters.Digits.ToString(CultureInfo.InvariantCulture)}"
                + $"&period={parameters.PeriodSeconds.ToString(CultureInfo.InvariantCulture)}";
        }

        /// <summary>Computes the HMAC of a time counter under a key, as RFC 4226 specifies.</summary>
        /// <param name="key">The shared secret.</param>
        /// <param name="counter">The time step counter.</param>
        /// <param name="algorithm">Which hash function to use.</param>
        /// <returns>The MAC, which the caller must wipe.</returns>
        private static byte[] Mac(byte[] key, long counter, TotpAlgorithm algorithm)
        {
            // The counter is the eight-byte big-endian message, exactly as RFC 4226 defines it.
            Span<byte> message = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(message, counter);

            return algorithm switch
            {
                TotpAlgorithm.Sha256 => HMACSHA256.HashData(key, message),
                TotpAlgorithm.Sha512 => HMACSHA512.HashData(key, message),
                _ => HMACSHA1.HashData(key, message)
            };
        }

        /// <summary>
        /// Reduces a MAC to a decimal code using the RFC 4226 dynamic truncation.
        /// </summary>
        /// <param name="mac">The MAC to truncate. Wiped before this returns.</param>
        /// <param name="parameters">How many digits the code has.</param>
        /// <remarks>
        /// The low nibble of the last byte chooses where to read four bytes from, and the top bit of the
        /// first of those is cleared so the result is positive on every platform. The modulus is a written
        /// constant rather than a computed power, so no floating-point rounding can reach the digits.
        /// </remarks>
        private static string Truncate(byte[] mac, TotpParameters parameters)
        {
            try
            {
                var offset = mac[^1] & 0x0F;

                var binary = ((mac[offset] & 0x7F) << 24)
                    | ((mac[offset + 1] & 0xFF) << 16)
                    | ((mac[offset + 2] & 0xFF) << 8)
                    | (mac[offset + 3] & 0xFF);

                return (binary % parameters.Modulus)
                    .ToString(CultureInfo.InvariantCulture)
                    .PadLeft(parameters.Digits, '0');
            }
            finally
            {
                CryptographicOperations.ZeroMemory(mac);
            }
        }

        /// <summary>What a caller must know about the identifiers they just asked for.</summary>
        /// <param name="spec">The options they were generated from.</param>
        private static IReadOnlyList<string> UuidAdvice(UuidSpec spec)
        {
            var advice = new List<string>
            {
                "A UUID is an identifier, not a credential. These are drawn from a cryptographically "
                + "secure generator, but they are meant to be logged, printed and put in URLs, so do not "
                + "use one as a session token, an API key or a password reset token.",
                "Uniqueness here is probabilistic rather than enforced. Anything that requires values to "
                + "be distinct still needs a unique constraint of its own."
            };

            if (spec.Version == UuidVersion.V7)
            {
                advice.Add(
                    "A version 7 value carries the time it was created, to the millisecond, readable by "
                    + "anyone who holds it. It also sorts in creation order, which makes the values either "
                    + "side of one guessable. Use version 4 where neither is acceptable.");
            }

            return advice;
        }

        /// <summary>What a caller must do for a TOTP secret to actually be a second factor.</summary>
        /// <param name="parameters">The parameters the secret is for.</param>
        /// <param name="bytes">Bytes of randomness in the secret.</param>
        private static IReadOnlyList<string> TotpSecretAdvice(TotpParameters parameters, int bytes)
        {
            var advice = new List<string>
            {
                "This secret is the entire second factor: anything holding it can produce valid codes "
                + "indefinitely. Store it encrypted, never in a log, and show it to the person enrolling "
                + "exactly once.",
                "The algorithm, digits and period must be enrolled alongside the secret. A code only "
                + "verifies when the authenticator and the server agree on all three.",
                "Whatever verifies these codes must rate-limit attempts and must refuse a code that has "
                + "already been used, or a six-digit code is guessable and replayable.",
                "The secret is returned once. This API does not store it and cannot produce it again."
            };

            if (parameters.Algorithm != TotpAlgorithm.Sha1)
            {
                advice.Add(
                    $"Many authenticator applications support only HMAC-SHA1 and silently compute SHA-1 "
                    + $"codes regardless of what the enrollment asks for. Confirm yours supports "
                    + $"{parameters.AlgorithmName} before enrolling anyone with it.");
            }

            if (parameters.PeriodSeconds != TotpParameters.RecommendedPeriodSeconds)
            {
                advice.Add(
                    $"A {parameters.PeriodSeconds} second period is not the {TotpParameters.RecommendedPeriodSeconds} "
                    + "second default, and some authenticators ignore the period entirely.");
            }

            if (parameters.Digits != 6)
            {
                advice.Add(
                    $"{parameters.Digits} digit codes are not universally supported; six is what an "
                    + "authenticator assumes when it cannot read the parameter.");
            }

            if (bytes < 20)
            {
                advice.Add(
                    $"{bytes * 8} bits is below the 160 RFC 4226 recommends for a shared secret. It is "
                    + "still above the 128-bit floor, but there is no reason to prefer a shorter secret.");
            }

            return advice;
        }

        /// <summary>What a caller must do with an enrollment URI.</summary>
        /// <param name="parameters">The parameters the enrollment carries.</param>
        private static IReadOnlyList<string> EnrollmentAdvice(TotpParameters parameters)
        {
            var advice = new List<string>
            {
                "The URI contains the shared secret, so a QR code rendered from it is a picture of the "
                + "second factor. Serve it over HTTPS, never log it, and do not let it be cached or "
                + "screenshotted into a support ticket.",
                "Confirm one code from the person's authenticator before you rely on the enrollment, or "
                + "someone who never completed the scan will be locked out.",
                "Store the secret encrypted on the server. The URI is for delivery only."
            };

            if (parameters.Algorithm != TotpAlgorithm.Sha1)
            {
                advice.Add(
                    $"Some authenticators ignore the algorithm parameter and compute HMAC-SHA1 anyway, "
                    + $"which would silently produce codes your server rejects. Confirm yours supports "
                    + $"{parameters.AlgorithmName}.");
            }

            return advice;
        }

        /// <summary>What this code is, and what it is not.</summary>
        private static IReadOnlyList<string> CodeAdvice() =>
        [
            "This computes a code from a secret you supplied; it verifies nothing and authenticates "
            + "nobody. It is here so an enrollment can be checked against what the authenticator shows.",
            "Verification belongs on your own server, against your own stored secret, with a small window "
            + "either side for clock drift, single-use enforcement and rate limiting.",
            "Compare codes with a fixed-time comparison, so a wrong code cannot be improved one digit at "
            + "a time."
        ];
    }
}
