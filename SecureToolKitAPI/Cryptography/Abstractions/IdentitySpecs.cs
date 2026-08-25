using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>Which RFC 9562 UUID layout to generate.</summary>
    public enum UuidVersion
    {
        /// <summary>
        /// Version 4: 122 random bits and nothing else. The right choice unless the values need to sort.
        /// </summary>
        V4,

        /// <summary>
        /// Version 7: a 48-bit millisecond timestamp followed by 74 random bits, so values generated later
        /// sort after values generated earlier. The timestamp is readable by anyone holding the value.
        /// </summary>
        V7
    }

    /// <summary>How a UUID is written out.</summary>
    public enum UuidFormat
    {
        /// <summary>The canonical form, <c>8-4-4-4-12</c> hexadecimal digits.</summary>
        Hyphenated,

        /// <summary>32 hexadecimal digits with no hyphens.</summary>
        Compact,

        /// <summary>The canonical form wrapped in braces, as Windows tooling writes it.</summary>
        Braced,

        /// <summary>The RFC 9562 URN form, <c>urn:uuid:</c> followed by the canonical form.</summary>
        Urn
    }

    /// <summary>The hash functions RFC 6238 allows a TOTP to be built on.</summary>
    /// <remarks>
    /// SHA-1 is the default because it is the only one every authenticator application implements. That is
    /// not a weakness here: HMAC-SHA-1 is unaffected by the collision attacks that ended SHA-1's use for
    /// signatures, and RFC 6238 still specifies it. The stronger options are available for a system whose
    /// authenticator is known to support them.
    /// </remarks>
    public enum TotpAlgorithm
    {
        /// <summary>HMAC-SHA-1, the default every authenticator supports.</summary>
        Sha1,

        /// <summary>HMAC-SHA-256. Supported by fewer authenticators.</summary>
        Sha256,

        /// <summary>HMAC-SHA-512. Supported by fewer authenticators still.</summary>
        Sha512
    }

    /// <summary>Options for a batch of UUIDs.</summary>
    /// <remarks>
    /// A UUID is an identifier, not a credential. Every value here is drawn from
    /// <see cref="RandomNumberGenerator"/>, so a version 4 value is unpredictable, but UUIDs are routinely
    /// logged, put in URLs and printed — the generator says so in its advisories rather than leaving a
    /// caller to use one as a bearer token.
    /// </remarks>
    public sealed record UuidSpec
    {
        /// <summary>Fewest UUIDs a request may ask for.</summary>
        public const int MinimumCount = 1;

        /// <summary>Most UUIDs a request may ask for, which bounds the response size.</summary>
        public const int MaximumCount = 100;

        /// <summary>How many to generate. Defaults to 1.</summary>
        public int Count { get; init; } = 1;

        /// <summary>Which layout to use. Defaults to <see cref="UuidVersion.V4"/>.</summary>
        public UuidVersion Version { get; init; } = UuidVersion.V4;

        /// <summary>How to write them out. Defaults to <see cref="UuidFormat.Hyphenated"/>.</summary>
        public UuidFormat Format { get; init; } = UuidFormat.Hyphenated;

        /// <summary>
        /// Writes the hexadecimal digits in uppercase. Defaults to <c>false</c>; RFC 9562 requires
        /// lowercase on output and case-insensitive comparison on input.
        /// </summary>
        public bool Uppercase { get; init; }

        /// <summary>
        /// Random bits in one value: 122 for version 4, and 74 for version 7, where the timestamp and the
        /// version and variant markers take up the rest.
        /// </summary>
        public int RandomBits => Version == UuidVersion.V7 ? 74 : 122;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            if (Count is < MinimumCount or > MaximumCount)
            {
                throw new CryptographicRequestException(
                    $"The number of UUIDs must be between {MinimumCount} and {MaximumCount}.");
            }

            if (!Enum.IsDefined(Version))
            {
                throw new CryptographicRequestException("The requested UUID version is not supported.");
            }

            if (!Enum.IsDefined(Format))
            {
                throw new CryptographicRequestException("The requested UUID format is not supported.");
            }
        }

        /// <summary>Describes the layout, for the response.</summary>
        /// <returns>A caller-safe description.</returns>
        public string Describe() =>
            Version == UuidVersion.V7
                ? "RFC 9562 version 7: a 48-bit millisecond timestamp followed by 74 random bits"
                : "RFC 9562 version 4: 122 random bits";
    }

    /// <summary>
    /// The parameters an authenticator and a server must agree on for a TOTP to verify: the hash function,
    /// how many digits a code has and how long each code lasts.
    /// </summary>
    /// <remarks>
    /// These are not secret and they are not options that can be changed later in isolation — a code only
    /// verifies when both sides use the same three values, so they travel with the secret rather than being
    /// assumed.
    /// </remarks>
    public sealed record TotpParameters
    {
        /// <summary>Fewest digits RFC 4226 allows in a code.</summary>
        public const int MinimumDigits = 6;

        /// <summary>Most digits this API will produce. Beyond eight, the truncation has no more bits to give.</summary>
        public const int MaximumDigits = 8;

        /// <summary>Shortest time step accepted.</summary>
        public const int MinimumPeriodSeconds = 15;

        /// <summary>Longest time step accepted.</summary>
        public const int MaximumPeriodSeconds = 300;

        /// <summary>The recommended time step, and the only one every authenticator assumes.</summary>
        public const int RecommendedPeriodSeconds = 30;

        /// <summary>Which hash function to use. Defaults to <see cref="TotpAlgorithm.Sha1"/>.</summary>
        public TotpAlgorithm Algorithm { get; init; } = TotpAlgorithm.Sha1;

        /// <summary>Digits in a code. Between 6 and 8; defaults to 6.</summary>
        public int Digits { get; init; } = 6;

        /// <summary>
        /// How many seconds each code is valid for. Between 15 and 300; defaults to 30, which is what an
        /// authenticator assumes when the enrollment does not say otherwise.
        /// </summary>
        public int PeriodSeconds { get; init; } = RecommendedPeriodSeconds;

        /// <summary>
        /// The key size RFC 6238 recommends for <see cref="Algorithm"/>: the hash output size, which is
        /// the largest key that adds any strength to an HMAC.
        /// </summary>
        public int RecommendedKeyBytes => Algorithm switch
        {
            TotpAlgorithm.Sha256 => 32,
            TotpAlgorithm.Sha512 => 64,
            _ => 20
        };

        /// <summary>
        /// The algorithm as an <c>otpauth</c> URI writes it, which is also how authenticators display it.
        /// </summary>
        public string AlgorithmName => Algorithm switch
        {
            TotpAlgorithm.Sha256 => "SHA256",
            TotpAlgorithm.Sha512 => "SHA512",
            _ => "SHA1"
        };

        /// <summary>
        /// The power of ten a truncated value is reduced modulo to get <see cref="Digits"/> digits. Written
        /// out rather than computed, so no floating-point rounding can reach the code.
        /// </summary>
        public int Modulus => Digits switch
        {
            7 => 10_000_000,
            8 => 100_000_000,
            _ => 1_000_000
        };

        /// <summary>Validates the parameters.</summary>
        /// <exception cref="CryptographicRequestException">A parameter is outside the supported range.</exception>
        public void Validate()
        {
            if (!Enum.IsDefined(Algorithm))
            {
                throw new CryptographicRequestException(
                    "The requested TOTP algorithm is not supported. Supported algorithms: SHA1, SHA256, SHA512.");
            }

            if (Digits is < MinimumDigits or > MaximumDigits)
            {
                throw new CryptographicRequestException(
                    $"The number of digits must be between {MinimumDigits} and {MaximumDigits}.");
            }

            if (PeriodSeconds is < MinimumPeriodSeconds or > MaximumPeriodSeconds)
            {
                throw new CryptographicRequestException(
                    $"The period must be between {MinimumPeriodSeconds} and {MaximumPeriodSeconds} seconds.");
            }
        }

        /// <summary>Describes the parameters, for the response.</summary>
        /// <returns>A caller-safe description; these values are not secret.</returns>
        public string Describe() =>
            $"HMAC-{AlgorithmName}, {Digits} digit codes, {PeriodSeconds} second time step";
    }

    /// <summary>Options for a TOTP shared secret.</summary>
    /// <remarks>
    /// The secret is the whole of the second factor: whoever holds it can produce codes indefinitely. It is
    /// generated once, shown to the person enrolling exactly once, and stored encrypted on the server.
    /// </remarks>
    public sealed record TotpSecretSpec
    {
        /// <summary>
        /// Fewest bytes accepted, 128 bits. RFC 4226 requires at least 128 bits and recommends 160.
        /// </summary>
        public const int MinimumBytes = 16;

        /// <summary>
        /// Most bytes accepted. Beyond the hash's block size the key is hashed down before use, so a
        /// larger secret is only harder to enroll.
        /// </summary>
        public const int MaximumBytes = 64;

        /// <summary>
        /// Bytes of randomness. Omit for the size recommended for the algorithm, which is 20 bytes for
        /// SHA-1.
        /// </summary>
        public int? Bytes { get; init; }

        /// <summary>The parameters the secret will be used with. Defaults to SHA-1, 6 digits, 30 seconds.</summary>
        public TotpParameters Parameters { get; init; } = new();

        /// <summary>The size that will be used: the caller's, or the recommendation for the algorithm.</summary>
        public int ResolvedBytes => Bytes ?? Parameters.RecommendedKeyBytes;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            Parameters.Validate();

            if (ResolvedBytes is < MinimumBytes or > MaximumBytes)
            {
                throw new CryptographicRequestException(
                    $"The secret size must be between {MinimumBytes} and {MaximumBytes} bytes.");
            }
        }
    }

    /// <summary>
    /// Options for a complete TOTP enrollment: the secret, the parameters, and the <c>otpauth</c> URI an
    /// authenticator application reads from a QR code.
    /// </summary>
    /// <remarks>
    /// The issuer and account name are what the person sees in their authenticator, so they are required:
    /// an entry labelled with neither is impossible to tell apart from the others once there are several.
    /// </remarks>
    public sealed record TotpEnrollmentSpec
    {
        /// <summary>Longest issuer or account name accepted.</summary>
        public const int MaximumLabelLength = 64;

        /// <summary>
        /// The service the code is for, as the person will see it in their authenticator, for example
        /// <c>Example Corp</c>.
        /// </summary>
        public string Issuer { get; init; } = string.Empty;

        /// <summary>
        /// Who the code belongs to, as the person will see it, usually an email address or a user name.
        /// </summary>
        public string Account { get; init; } = string.Empty;

        /// <summary>
        /// An existing Base32 secret to build the enrollment around. Omit to generate a new one, which is
        /// the usual case; supply one only when re-issuing the URI for a secret that already exists.
        /// </summary>
        public string? Secret { get; init; }

        /// <summary>Bytes of randomness for a generated secret. Ignored when <see cref="Secret"/> is supplied.</summary>
        public int? Bytes { get; init; }

        /// <summary>The parameters to enroll with. Defaults to SHA-1, 6 digits, 30 seconds.</summary>
        public TotpParameters Parameters { get; init; } = new();

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is missing, too long or unusable.</exception>
        public void Validate()
        {
            ValidateLabel(Issuer, "issuer");
            ValidateLabel(Account, "account name");

            if (Secret is null)
            {
                new TotpSecretSpec { Bytes = Bytes, Parameters = Parameters }.Validate();

                return;
            }

            // A supplied secret settles the size, so a size option alongside it would be ignored — which
            // is worth reporting rather than doing silently.
            if (Bytes is not null)
            {
                throw new CryptographicRequestException(
                    "A secret and a secret size were both supplied. Omit the size to use the supplied secret, "
                    + "or omit the secret to generate one of that size.");
            }

            new TotpCodeSpec { Secret = Secret, Parameters = Parameters }.ValidateSecret();
        }

        /// <summary>
        /// Checks that a label is present, short enough, and free of characters that would change how an
        /// <c>otpauth</c> URI parses.
        /// </summary>
        /// <param name="value">The label to check.</param>
        /// <param name="description">Caller-facing name of the label.</param>
        /// <exception cref="CryptographicRequestException">The label is unusable.</exception>
        private static void ValidateLabel(string value, string description)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new CryptographicRequestException($"The {description} is required.");
            }

            if (value.Length > MaximumLabelLength)
            {
                throw new CryptographicRequestException(
                    $"The {description} must be at most {MaximumLabelLength} characters.");
            }

            // A colon separates the issuer from the account in the URI label, so one inside either part
            // would silently split it somewhere else.
            if (value.Contains(':', StringComparison.Ordinal))
            {
                throw new CryptographicRequestException($"The {description} must not contain a colon.");
            }

            if (value.Any(char.IsControl))
            {
                throw new CryptographicRequestException(
                    $"The {description} must not contain control characters.");
            }
        }
    }

    /// <summary>Options for computing a TOTP code from a secret.</summary>
    /// <remarks>
    /// <para>
    /// This exists to check an enrollment end to end: the code returned here should be the one the person's
    /// authenticator is showing. It is not an authentication endpoint and it verifies nothing — the secret
    /// is supplied by the caller, so anything with the secret can already produce codes.
    /// </para>
    /// <para>
    /// The secret arrives as Base32 because that is the form an authenticator and this API's own secret
    /// endpoint both use.
    /// </para>
    /// </remarks>
    public sealed record TotpCodeSpec
    {
        /// <summary>
        /// Fewest bytes a supplied secret may decode to, 80 bits — the floor RFC 4226 sets for a shared
        /// secret. Below this the second factor is guessable, so a short secret is refused rather than used.
        /// </summary>
        public const int MinimumKeyBytes = 10;

        /// <summary>Most bytes a supplied secret may decode to, which bounds the work done per request.</summary>
        public const int MaximumKeyBytes = 128;

        /// <summary>The shared secret, Base32 encoded. Hyphens, spaces and lowercase are accepted.</summary>
        public string Secret { get; init; } = string.Empty;

        /// <summary>The parameters the secret was enrolled with. Defaults to SHA-1, 6 digits, 30 seconds.</summary>
        public TotpParameters Parameters { get; init; } = new();

        /// <summary>
        /// Unix time in seconds to compute the code for. Omit for now, which is what a caller checking an
        /// enrollment wants.
        /// </summary>
        public long? UnixTimeSeconds { get; init; }

        /// <summary>Validates the options.</summary>
        /// <exception cref="CryptographicRequestException">An option is missing or unusable.</exception>
        public void Validate()
        {
            Parameters.Validate();
            ValidateSecret();

            // Rejected rather than clamped: a negative Unix time is a caller mistake, and returning a code
            // for a moment before 1970 would look like a working answer.
            if (UnixTimeSeconds is < 0)
            {
                throw new CryptographicRequestException("The time must not be negative.");
            }
        }

        /// <summary>
        /// Checks that the secret is present and is Base32 that decodes to a usable key size.
        /// </summary>
        /// <exception cref="CryptographicRequestException">The secret is missing, malformed or too short.</exception>
        /// <remarks>
        /// The decoded key is wiped immediately: this only measures it. The generator decodes again when it
        /// actually needs the bytes, which costs nothing and keeps key material out of the options object.
        /// </remarks>
        internal void ValidateSecret()
        {
            if (string.IsNullOrWhiteSpace(Secret))
            {
                throw new CryptographicRequestException("The secret is required.");
            }

            // The message says what is wrong with the value without repeating any of it.
            if (!Base32Text.TryDecode(Secret, out var key))
            {
                throw new CryptographicRequestException("The secret is not valid Base32.");
            }

            try
            {
                if (key.Length < MinimumKeyBytes)
                {
                    throw new CryptographicRequestException(
                        $"The secret must decode to at least {MinimumKeyBytes} bytes.");
                }

                if (key.Length > MaximumKeyBytes)
                {
                    throw new CryptographicRequestException(
                        $"The secret must decode to at most {MaximumKeyBytes} bytes.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    /// <summary>Options for rendering bytes as Base32.</summary>
    /// <remarks>
    /// Base32 is an encoding, not encryption: it hides nothing, and the result is exactly as sensitive as
    /// the input. The endpoint exists because a TOTP secret, a recovery code or a device identifier often
    /// has to be written in a form a person can read back accurately.
    /// </remarks>
    public sealed record Base32Spec
    {
        /// <summary>Most bytes that may be encoded in one request.</summary>
        public const int MaximumBytes = 4096;

        /// <summary>Text to encode, taken as UTF-8. Mutually exclusive with <see cref="Base64"/>.</summary>
        public string? Text { get; init; }

        /// <summary>
        /// Bytes to encode, given as Base64, for input that is not text. Mutually exclusive with
        /// <see cref="Text"/>.
        /// </summary>
        public string? Base64 { get; init; }

        /// <summary>
        /// Pads the result to a whole block with <c>=</c>, as RFC 4648 requires. Defaults to <c>true</c>;
        /// an <c>otpauth</c> URI omits the padding.
        /// </summary>
        public bool Padding { get; init; } = true;

        /// <summary>
        /// Writes the result in lowercase. Defaults to <c>false</c>; the RFC 4648 alphabet is uppercase.
        /// </summary>
        public bool Lowercase { get; init; }

        /// <summary>Validates the options.</summary>
        /// <exception cref="CryptographicRequestException">
        /// Neither input was supplied, both were, the Base64 is malformed, or the input is too large.
        /// </exception>
        public void Validate() => _ = Decode();

        /// <summary>Resolves the options to the bytes to encode.</summary>
        /// <returns>The bytes, which may be empty when the caller supplied empty text.</returns>
        /// <exception cref="CryptographicRequestException">The options are not usable.</exception>
        /// <remarks>
        /// Validation and resolution are the same operation here — the only way to know the Base64 is
        /// usable is to decode it — so <see cref="Validate"/> defers to this rather than decoding twice.
        /// </remarks>
        public byte[] Decode()
        {
            if (Text is not null && Base64 is not null)
            {
                throw new CryptographicRequestException("Supply either text or Base64 bytes, not both.");
            }

            if (Text is not null)
            {
                var bytes = Base64Text.ToUtf8(Text);

                return Within(bytes);
            }

            if (Base64 is null)
            {
                throw new CryptographicRequestException("Either text or Base64 bytes are required.");
            }

            if (!Base64Text.TryDecode(Base64, out var decoded))
            {
                throw new CryptographicRequestException("The supplied bytes are not valid Base64.");
            }

            return Within(decoded);
        }

        /// <summary>Checks the resolved input against the size limit.</summary>
        /// <param name="bytes">The resolved bytes.</param>
        /// <exception cref="CryptographicRequestException">The input is larger than the limit.</exception>
        private static byte[] Within(byte[] bytes) =>
            bytes.Length > MaximumBytes
                ? throw new CryptographicRequestException(
                    $"At most {MaximumBytes} bytes can be encoded in one request.")
                : bytes;
    }

    /// <summary>
    /// Reads the caller-facing spelling of the identity options and turns it into the corresponding
    /// option, so an unknown value is reported as a bad request rather than silently falling back to a
    /// default.
    /// </summary>
    /// <remarks>
    /// Matching ignores case, hyphens, underscores and spaces, so <c>sha256</c>, <c>SHA-256</c> and
    /// <c>Sha_256</c> all resolve to the same option. An omitted value means "use the default".
    /// </remarks>
    public static class IdentityOptions
    {
        /// <summary>Resolves a UUID version name, for example <c>v4</c>.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved version.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported version.</exception>
        public static UuidVersion ParseUuidVersion(string? value) =>
            OptionName.Parse(value, UuidVersion.V4, "UUID version");

        /// <summary>Resolves a UUID format name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved format.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported format.</exception>
        public static UuidFormat ParseUuidFormat(string? value) =>
            OptionName.Parse(value, UuidFormat.Hyphenated, "UUID format");

        /// <summary>Resolves a TOTP algorithm name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved algorithm.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported algorithm.</exception>
        public static TotpAlgorithm ParseTotpAlgorithm(string? value) =>
            OptionName.Parse(value, TotpAlgorithm.Sha1, "TOTP algorithm");
    }
}
