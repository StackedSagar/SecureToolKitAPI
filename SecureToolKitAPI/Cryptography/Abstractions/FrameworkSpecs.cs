using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// The ciphers a Laravel application can be configured with, which is what decides how long its
    /// <c>APP_KEY</c> must be.
    /// </summary>
    /// <remarks>
    /// The key is sized by the cipher rather than by the caller: Laravel refuses to boot when the decoded
    /// key length does not match <c>config('app.cipher')</c>, so a 16-byte key under <c>aes-256-cbc</c>
    /// would be an application that will not start rather than an application that is slightly weaker.
    /// </remarks>
    public enum LaravelCipher
    {
        /// <summary>AES-256 in CBC mode, Laravel's default. Needs a 32-byte key.</summary>
        Aes256Cbc,

        /// <summary>AES-128 in CBC mode. Needs a 16-byte key.</summary>
        Aes128Cbc,

        /// <summary>AES-256 in GCM mode, available in current Laravel versions. Needs a 32-byte key.</summary>
        Aes256Gcm,

        /// <summary>AES-128 in GCM mode. Needs a 16-byte key.</summary>
        Aes128Gcm
    }

    /// <summary>
    /// Options for a Django <c>SECRET_KEY</c>: the value Django signs sessions, password reset tokens,
    /// messages and CSRF tokens with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The alphabet is not an option because it is Django's own — the 50 characters
    /// <c>get_random_secret_key()</c> samples from — so a key generated here is the same shape as one
    /// <c>django-admin startproject</c> would have written. Only the length can be varied, and the default
    /// is Django's 50 characters, about 282 bits.
    /// </para>
    /// <para>
    /// Rotating this key logs every session out and invalidates every password reset link that has not been
    /// used yet, which is why it is worth generating once and storing properly rather than regenerating
    /// casually.
    /// </para>
    /// </remarks>
    public sealed record DjangoSecretKeySpec
    {
        /// <summary>
        /// Shortest key this API will generate, 32 characters — about 180 bits, still far beyond what any
        /// signature Django produces needs.
        /// </summary>
        public const int MinimumLength = 32;

        /// <summary>Longest key this API will generate.</summary>
        public const int MaximumLength = 128;

        /// <summary>Characters in the key. Defaults to 50, which is Django's own length.</summary>
        public int Length { get; init; } = 50;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">The length is outside the supported range.</exception>
        public void Validate()
        {
            if (Length is < MinimumLength or > MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"The key length must be between {MinimumLength} and {MaximumLength} characters.");
            }
        }

        /// <summary>Describes what the key is drawn from, for the response.</summary>
        /// <returns>A caller-safe description; no key is generated and none is revealed.</returns>
        public string Describe() =>
            $"{Length} characters sampled from Django's own alphabet of lowercase letters, digits and "
            + $"punctuation ({FrameworkAlphabets.DjangoSecretKey.Length} symbols)";
    }

    /// <summary>
    /// Options for a Flask <c>SECRET_KEY</c>: the value Flask signs its session cookie with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Flask puts no constraint on the shape of this value, so it is sized in bytes of randomness and then
    /// rendered. The default is 32 bytes as hexadecimal, which is exactly what
    /// <c>secrets.token_hex(32)</c> produces and what the Flask documentation tells you to run.
    /// </para>
    /// <para>
    /// A Flask session cookie is signed, not encrypted: its contents are readable by the client. This key
    /// stops the client changing them, and nothing more.
    /// </para>
    /// </remarks>
    public sealed record FlaskSecretKeySpec
    {
        /// <summary>Fewest random bytes this API will generate for a signing key, 128 bits.</summary>
        public const int MinimumBytes = 16;

        /// <summary>Most random bytes this API will generate in one key, 1024 bits.</summary>
        public const int MaximumBytes = 128;

        /// <summary>Bytes of randomness in the key. Defaults to 32, or 256 bits.</summary>
        public int Bytes { get; init; } = 32;

        /// <summary>
        /// How the random bytes are rendered. Defaults to <see cref="SecretEncoding.Hex"/>, which matches
        /// the <c>secrets.token_hex</c> recipe in Flask's own documentation.
        /// </summary>
        public SecretEncoding Encoding { get; init; } = SecretEncoding.Hex;

        /// <summary>Validates the options before any randomness is drawn.</summary>
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
        }

        /// <summary>Describes how the key will be rendered, for the response.</summary>
        /// <returns>A caller-safe description; no key is generated and none is revealed.</returns>
        public string Describe() => $"{Bytes * 8} random bits, {SecretText.Describe(Encoding)}";
    }

    /// <summary>
    /// Options for a Laravel <c>APP_KEY</c>: the value Laravel encrypts cookies, sessions and signed URLs
    /// with, and the one <c>php artisan key:generate</c> writes.
    /// </summary>
    /// <remarks>
    /// The only option is the cipher, because that is the only thing that changes the key: Laravel expects
    /// the literal prefix <c>base64:</c> followed by the standard Base64 of a key of exactly the length the
    /// configured cipher needs.
    /// </remarks>
    public sealed record LaravelAppKeySpec
    {
        /// <summary>
        /// The cipher the application is configured with. Defaults to
        /// <see cref="LaravelCipher.Aes256Cbc"/>, which is Laravel's default.
        /// </summary>
        public LaravelCipher Cipher { get; init; } = LaravelCipher.Aes256Cbc;

        /// <summary>Bytes the configured cipher's key must contain.</summary>
        public int KeyBytes => Cipher is LaravelCipher.Aes128Cbc or LaravelCipher.Aes128Gcm ? 16 : 32;

        /// <summary>The cipher spelled the way <c>config/app.php</c> spells it.</summary>
        public string CipherName => Cipher switch
        {
            LaravelCipher.Aes128Cbc => "aes-128-cbc",
            LaravelCipher.Aes256Gcm => "aes-256-gcm",
            LaravelCipher.Aes128Gcm => "aes-128-gcm",
            _ => "aes-256-cbc"
        };

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">The cipher is not one of the supported ones.</exception>
        public void Validate()
        {
            if (!Enum.IsDefined(Cipher))
            {
                throw new CryptographicRequestException("The requested cipher is not supported.");
            }
        }

        /// <summary>Describes how the key will be rendered, for the response.</summary>
        /// <returns>A caller-safe description; no key is generated and none is revealed.</returns>
        public string Describe() =>
            $"{KeyBytes * 8} random bits for {CipherName}, Base64 encoded behind Laravel's base64: prefix";
    }

    /// <summary>
    /// Options for the eight WordPress authentication keys and salts that belong in <c>wp-config.php</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The eight names are fixed by WordPress, so the only option is how long each value is. The default is
    /// 64 characters over 92 symbols — about 417 bits each — which is what WordPress's own salt service
    /// hands out.
    /// </para>
    /// <para>
    /// All eight are generated independently. Reusing one value across two constants, or copying a
    /// published example, defeats the point of having eight.
    /// </para>
    /// </remarks>
    public sealed record WordPressSaltSpec
    {
        /// <summary>Shortest value this API will generate for a salt.</summary>
        public const int MinimumLength = 32;

        /// <summary>Longest value this API will generate for a salt.</summary>
        public const int MaximumLength = 128;

        /// <summary>Characters in each of the eight values. Defaults to 64, as WordPress uses.</summary>
        public int Length { get; init; } = 64;

        /// <summary>Validates the options before any randomness is drawn.</summary>
        /// <exception cref="CryptographicRequestException">The length is outside the supported range.</exception>
        public void Validate()
        {
            if (Length is < MinimumLength or > MaximumLength)
            {
                throw new CryptographicRequestException(
                    $"The salt length must be between {MinimumLength} and {MaximumLength} characters.");
            }
        }

        /// <summary>Describes what each value is drawn from, for the response.</summary>
        /// <returns>A caller-safe description; no salt is generated and none is revealed.</returns>
        public string Describe() =>
            $"{Length} characters sampled from WordPress's own alphabet of letters, digits and punctuation "
            + $"({FrameworkAlphabets.WordPressSalt.Length} symbols)";
    }

    /// <summary>
    /// Reads the caller-facing spelling of the framework options and turns it into the corresponding
    /// option, so an unknown value is reported as a bad request rather than silently falling back to a
    /// default.
    /// </summary>
    /// <remarks>
    /// Matching ignores case, hyphens, underscores and spaces, so <c>aes-256-cbc</c>, <c>AES256CBC</c> and
    /// <c>Aes256Cbc</c> all resolve to the same cipher. An omitted value means "use the default".
    /// </remarks>
    public static class FrameworkOptions
    {
        /// <summary>Resolves a Laravel cipher name.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved cipher.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported cipher.</exception>
        public static LaravelCipher ParseLaravelCipher(string? value) =>
            OptionName.Parse(value, LaravelCipher.Aes256Cbc, "cipher");
    }
}
