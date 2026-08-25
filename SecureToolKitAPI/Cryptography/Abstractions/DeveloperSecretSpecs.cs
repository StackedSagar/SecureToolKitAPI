using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>How random material is rendered as text.</summary>
    /// <remarks>
    /// The encoding changes how many characters a value has, not how much entropy it carries: the
    /// randomness is in the bytes. <see cref="Base62"/> is the exception — there is no useful way to
    /// re-base raw bytes into 62 symbols, so a Base62 value is sampled character by character from the
    /// alphabet instead, using enough characters to carry at least the requested number of bits.
    /// </remarks>
    public enum SecretEncoding
    {
        /// <summary>Base64 with the URL-safe alphabet and no padding. Safe in URLs, headers and JSON.</summary>
        Base64Url,

        /// <summary>Standard Base64 with padding.</summary>
        Base64,

        /// <summary>Lowercase hexadecimal.</summary>
        Hex,

        /// <summary>Uppercase hexadecimal.</summary>
        HexUpper,

        /// <summary>Digits and letters only, which survives being read aloud, logged or double-clicked.</summary>
        Base62
    }

    /// <summary>The HMAC algorithms a JWT signing secret can be generated for.</summary>
    /// <remarks>
    /// RFC 7518 requires a key at least as long as the hash output for these algorithms, so the size is
    /// determined by the algorithm rather than left to the caller.
    /// </remarks>
    public enum JwtAlgorithm
    {
        /// <summary>HMAC with SHA-256. Needs a 256-bit key.</summary>
        HS256,

        /// <summary>HMAC with SHA-384. Needs a 384-bit key.</summary>
        HS384,

        /// <summary>HMAC with SHA-512. Needs a 512-bit key.</summary>
        HS512
    }

    /// <summary>The kinds of opaque OAuth 2.0 value this API generates.</summary>
    /// <remarks>
    /// They differ in how long they live and how they must be stored, which is why each one carries its
    /// own default size and its own advisories rather than being one generic token.
    /// </remarks>
    public enum OAuthTokenKind
    {
        /// <summary>A short-lived bearer access token.</summary>
        AccessToken,

        /// <summary>A long-lived refresh token, which is the highest-value of these values.</summary>
        RefreshToken,

        /// <summary>A confidential client's secret.</summary>
        ClientSecret,

        /// <summary>A single-use authorization code.</summary>
        AuthorizationCode
    }

    /// <summary>The alphabets a random string can be sampled from.</summary>
    public enum RandomStringAlphabet
    {
        /// <summary>Digits and both letter cases, 62 symbols.</summary>
        Alphanumeric,

        /// <summary>Both letter cases, 52 symbols.</summary>
        Letters,

        /// <summary>Lowercase letters, 26 symbols.</summary>
        Lowercase,

        /// <summary>Uppercase letters, 26 symbols.</summary>
        Uppercase,

        /// <summary>Digits, 10 symbols.</summary>
        Digits,

        /// <summary>Lowercase hexadecimal, 16 symbols.</summary>
        Hex,

        /// <summary>Uppercase hexadecimal, 16 symbols.</summary>
        HexUpper,

        /// <summary>The URL-safe Base64 alphabet, 64 symbols.</summary>
        Base64Url,

        /// <summary>An alphabet supplied by the caller.</summary>
        Custom,
    }

    /// <summary>
    /// Options for a secret whose strength is stated in random bytes: an API key, an OAuth token or an
    /// imitated AI provider key.
    /// </summary>
    /// <remarks>
    /// <see cref="Bytes"/> is the amount of randomness requested, not the length of the result. The
    /// number of characters follows from <see cref="Encoding"/>, and a Base62 value is given enough
    /// characters to carry at least that many bits, so no encoding delivers less than was asked for.
    /// </remarks>
    public sealed record ByteSecretSpec
    {
        /// <summary>Fewest random bytes this API will generate for a machine credential, 128 bits.</summary>
        public const int MinimumBytes = 16;

        /// <summary>Most random bytes this API will generate in one value, 1024 bits.</summary>
        public const int MaximumBytes = 128;

        /// <summary>Longest prefix that may be placed in front of the random part.</summary>
        public const int MaximumPrefixLength = 24;

        /// <summary>Characters a prefix may contain, beyond letters and digits.</summary>
        private const string PrefixPunctuation = "-_.";

        /// <summary>Bytes of randomness to generate. Between 16 and 128; defaults to 32, or 256 bits.</summary>
        public int Bytes { get; init; } = 32;

        /// <summary>How the random bytes are rendered. Defaults to <see cref="SecretEncoding.Base64Url"/>.</summary>
        public SecretEncoding Encoding { get; init; } = SecretEncoding.Base64Url;

        /// <summary>
        /// Text placed in front of the random part, for example <c>sk_live_</c>, so a leaked key can be
        /// recognised and scanned for. Not secret and not counted towards the entropy. Defaults to none.
        /// </summary>
        public string Prefix { get; init; } = string.Empty;

        /// <summary>
        /// Validates the options before any randomness is drawn.
        /// </summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            if (Bytes is < MinimumBytes or > MaximumBytes)
            {
                throw new CryptographicRequestException(
                    $"The requested size must be between {MinimumBytes} and {MaximumBytes} bytes.");
            }

            if (!Enum.IsDefined(Encoding))
            {
                throw new CryptographicRequestException("The requested encoding is not supported.");
            }

            if (Prefix.Length > MaximumPrefixLength)
            {
                throw new CryptographicRequestException(
                    $"The prefix must be at most {MaximumPrefixLength} characters.");
            }

            // A prefix ends up in URLs, headers and log lines that the secret itself must never reach, so
            // it is restricted to characters that need no escaping anywhere.
            if (!Prefix.All(character =>
                    char.IsAsciiLetterOrDigit(character)
                    || PrefixPunctuation.Contains(character, StringComparison.Ordinal)))
            {
                throw new CryptographicRequestException(
                    "The prefix may contain only letters, digits, hyphens, underscores and dots.");
            }
        }
    }

    /// <summary>Options for a JWT signing secret.</summary>
    public sealed record JwtSecretSpec
    {
        /// <summary>The algorithm the secret will sign with. Defaults to <see cref="JwtAlgorithm.HS256"/>.</summary>
        public JwtAlgorithm Algorithm { get; init; } = JwtAlgorithm.HS256;

        /// <summary>
        /// How the secret is rendered. Defaults to <see cref="SecretEncoding.Base64"/>, which is what
        /// most JWT libraries and configuration files expect.
        /// </summary>
        public SecretEncoding Encoding { get; init; } = SecretEncoding.Base64;

        /// <summary>
        /// Key size in bytes for <see cref="Algorithm"/>: the hash output size, which is the smallest key
        /// RFC 7518 allows for that algorithm and the largest that adds any strength.
        /// </summary>
        public int KeySizeBytes => Algorithm switch
        {
            JwtAlgorithm.HS384 => 48,
            JwtAlgorithm.HS512 => 64,
            _ => 32
        };

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is not supported.</exception>
        public void Validate()
        {
            if (!Enum.IsDefined(Algorithm))
            {
                throw new CryptographicRequestException(
                    "The requested JWT algorithm is not supported. Supported algorithms: HS256, HS384, HS512.");
            }

            if (!Enum.IsDefined(Encoding))
            {
                throw new CryptographicRequestException("The requested encoding is not supported.");
            }
        }
    }

    /// <summary>Options for an opaque OAuth 2.0 value.</summary>
    public sealed record OAuthTokenSpec
    {
        /// <summary>What the value is for. Defaults to <see cref="OAuthTokenKind.AccessToken"/>.</summary>
        public OAuthTokenKind Kind { get; init; } = OAuthTokenKind.AccessToken;

        /// <summary>
        /// Bytes of randomness, between 16 and 128. Omit to use the default for <see cref="Kind"/>.
        /// </summary>
        public int? Bytes { get; init; }

        /// <summary>
        /// How the value is rendered. Defaults to <see cref="SecretEncoding.Base64Url"/>, which matches
        /// the character set RFC 6750 defines for a bearer token.
        /// </summary>
        public SecretEncoding Encoding { get; init; } = SecretEncoding.Base64Url;

        /// <summary>
        /// The size that will be used: the caller's, or the default for <see cref="Kind"/>. A refresh
        /// token and a client secret get more because they live longest.
        /// </summary>
        public int ResolvedBytes => Bytes ?? Kind switch
        {
            OAuthTokenKind.RefreshToken => 64,
            OAuthTokenKind.ClientSecret => 48,
            _ => 32
        };

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is not supported.</exception>
        public void Validate()
        {
            if (!Enum.IsDefined(Kind))
            {
                throw new CryptographicRequestException("The requested token kind is not supported.");
            }

            // The size and encoding rules are the same as any other machine credential, so they are
            // checked in one place rather than restated here.
            new ByteSecretSpec { Bytes = ResolvedBytes, Encoding = Encoding }.Validate();
        }
    }

    /// <summary>Options for the random values a WebAuthn registration needs.</summary>
    public sealed record WebAuthnSpec
    {
        /// <summary>Fewest bytes either value may have. The WebAuthn specification requires at least 16 for a challenge.</summary>
        public const int MinimumBytes = 16;

        /// <summary>Most bytes either value may have. A user handle is capped at 64 bytes by the specification.</summary>
        public const int MaximumBytes = 64;

        /// <summary>Bytes of randomness in the challenge. Between 16 and 64; defaults to 32.</summary>
        public int ChallengeBytes { get; init; } = 32;

        /// <summary>
        /// Bytes of randomness in the user handle. Between 16 and 64; defaults to 64, the largest the
        /// specification allows.
        /// </summary>
        public int UserHandleBytes { get; init; } = 64;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">A size is outside the supported range.</exception>
        public void Validate()
        {
            if (ChallengeBytes is < MinimumBytes or > MaximumBytes)
            {
                throw new CryptographicRequestException(
                    $"The challenge size must be between {MinimumBytes} and {MaximumBytes} bytes.");
            }

            if (UserHandleBytes is < MinimumBytes or > MaximumBytes)
            {
                throw new CryptographicRequestException(
                    $"The user handle size must be between {MinimumBytes} and {MaximumBytes} bytes.");
            }
        }
    }

    /// <summary>Options for a random string of a requested length.</summary>
    /// <remarks>
    /// Unlike the other developer secrets, the length here is a character count, because that is what a
    /// caller filling a fixed-width field is working with. The entropy reported is what that many
    /// characters from the chosen alphabet actually carries.
    /// </remarks>
    public sealed record RandomStringSpec
    {
        /// <summary>Shortest string this API will generate.</summary>
        public const int MinimumLength = 1;

        /// <summary>Longest string this API will generate.</summary>
        public const int MaximumLength = 4096;

        /// <summary>Most characters a custom alphabet may contain.</summary>
        public const int MaximumAlphabetLength = 256;

        /// <summary>Number of characters to generate. Between 1 and 4096; defaults to 32.</summary>
        public int Length { get; init; } = 32;

        /// <summary>
        /// Which alphabet to sample from. Defaults to <see cref="RandomStringAlphabet.Alphanumeric"/>.
        /// </summary>
        public RandomStringAlphabet Alphabet { get; init; } = RandomStringAlphabet.Alphanumeric;

        /// <summary>
        /// The alphabet to sample from when <see cref="Alphabet"/> is
        /// <see cref="RandomStringAlphabet.Custom"/>. Defaults to none.
        /// </summary>
        public string CustomAlphabet { get; init; } = string.Empty;

        /// <summary>The characters this specification samples from.</summary>
        /// <exception cref="CryptographicRequestException">The options are not usable.</exception>
        public string Characters() =>
            Alphabet == RandomStringAlphabet.Custom
                ? CustomAlphabet
                : SecretText.Alphabet(Alphabet);

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">An option is outside the supported range.</exception>
        public void Validate()
        {
            if (Length is < MinimumLength or > MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"The length must be between {MinimumLength} and {MaximumLength} characters.");
            }

            if (!Enum.IsDefined(Alphabet))
            {
                throw new CryptographicRequestException("The requested alphabet is not supported.");
            }

            if (Alphabet != RandomStringAlphabet.Custom)
            {
                // Silently ignoring a supplied alphabet would hand back a value the caller did not ask
                // for, so the mismatch is reported instead.
                if (CustomAlphabet.Length > 0)
                {
                    throw new CryptographicRequestException(
                        "A custom alphabet was supplied. Set the alphabet to 'custom' to use it.");
                }

                return;
            }

            if (CustomAlphabet.Length is < 2 or > MaximumAlphabetLength)
            {
                throw new CryptographicRequestException(
                    $"A custom alphabet must contain between 2 and {MaximumAlphabetLength} characters.");
            }

            if (CustomAlphabet.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            {
                throw new CryptographicRequestException(
                    "A custom alphabet must not contain whitespace or control characters.");
            }

            // A repeated character would be twice as likely to be chosen, which would make the reported
            // entropy an overstatement.
            if (CustomAlphabet.Distinct().Count() != CustomAlphabet.Length)
            {
                throw new CryptographicRequestException(
                    "A custom alphabet must not contain the same character twice.");
            }
        }
    }

    /// <summary>
    /// Reads the caller-facing spelling of the developer-secret options and turns it into the
    /// corresponding option, so an unknown value is reported as a bad request rather than silently
    /// falling back to a default.
    /// </summary>
    /// <remarks>
    /// Matching ignores case, hyphens, underscores and spaces, so <c>base64url</c>, <c>Base64-Url</c> and
    /// <c>BASE64_URL</c> all resolve to the same option. An omitted value means "use the default".
    /// </remarks>
    public static class DeveloperSecretOptions
    {
        /// <summary>Resolves an encoding name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <param name="fallback">The encoding to use when none was supplied.</param>
        /// <exception cref="CryptographicRequestException">The name is not a supported encoding.</exception>
        public static SecretEncoding ParseEncoding(
            string? value,
            SecretEncoding fallback = SecretEncoding.Base64Url) =>
            OptionName.Parse(value, fallback, "encoding");

        /// <summary>Resolves a JWT algorithm name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <exception cref="CryptographicRequestException">The name is not a supported algorithm.</exception>
        public static JwtAlgorithm ParseJwtAlgorithm(string? value) =>
            OptionName.Parse(value, JwtAlgorithm.HS256, "JWT algorithm");

        /// <summary>Resolves an OAuth token kind.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <exception cref="CryptographicRequestException">The name is not a supported kind.</exception>
        public static OAuthTokenKind ParseOAuthTokenKind(string? value) =>
            OptionName.Parse(value, OAuthTokenKind.AccessToken, "token kind");

        /// <summary>Resolves an alphabet name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <exception cref="CryptographicRequestException">The name is not a supported alphabet.</exception>
        public static RandomStringAlphabet ParseAlphabet(string? value) =>
            OptionName.Parse(value, RandomStringAlphabet.Alphanumeric, "alphabet");
    }
}
