using System.Text.Json.Serialization;

namespace SecureToolKitAPI.Contracts.Framework
{
    /// <summary>
    /// Options for a Django <c>SECRET_KEY</c>. Every member is optional; omit the body entirely for the
    /// 50-character key Django's own <c>get_random_secret_key()</c> produces.
    /// </summary>
    /// <remarks>
    /// The alphabet is not an option because it is Django's own, so a key generated here has the same shape
    /// as one <c>django-admin startproject</c> would have written. Values outside the documented range are
    /// reported as a 400 problem response rather than being clamped silently.
    /// </remarks>
    public sealed record DjangoSecretKeyRequest
    {
        /// <summary>Characters in the key. Between 32 and 128; defaults to 50, Django's own length.</summary>
        public int? Length { get; init; }
    }

    /// <summary>
    /// Options for a Flask <c>SECRET_KEY</c>. Every member is optional; omit the body entirely for 32 random
    /// bytes as hexadecimal, which is what <c>secrets.token_hex(32)</c> gives you.
    /// </summary>
    public sealed record FlaskSecretKeyRequest
    {
        /// <summary>Bytes of randomness. Between 16 and 128; defaults to 32, which is 256 bits.</summary>
        public int? Bytes { get; init; }

        /// <summary>
        /// How the random bytes are rendered: <c>hex</c>, <c>hexUpper</c>, <c>base64</c>, <c>base64url</c>
        /// or <c>base62</c>. Defaults to <c>hex</c>, matching the recipe in Flask's documentation. Flask
        /// puts no constraint on the shape of this value, so any of these work.
        /// </summary>
        public string? Encoding { get; init; }
    }

    /// <summary>
    /// Options for a Laravel <c>APP_KEY</c>. Every member is optional; omit the body entirely for a key
    /// sized for Laravel's default <c>aes-256-cbc</c>.
    /// </summary>
    /// <remarks>
    /// The length is decided by the cipher rather than by the caller, because Laravel refuses to boot when
    /// the decoded key length does not match <c>config('app.cipher')</c>.
    /// </remarks>
    public sealed record LaravelAppKeyRequest
    {
        /// <summary>
        /// The cipher the application is configured with: <c>aes-256-cbc</c>, <c>aes-128-cbc</c>,
        /// <c>aes-256-gcm</c> or <c>aes-128-gcm</c>. Matching ignores case, hyphens and underscores.
        /// Defaults to <c>aes-256-cbc</c>, which is Laravel's default.
        /// </summary>
        public string? Cipher { get; init; }
    }

    /// <summary>
    /// Options for the eight WordPress authentication keys and salts. Every member is optional; omit the
    /// body entirely for the 64-character values WordPress's own salt service hands out.
    /// </summary>
    /// <remarks>
    /// The eight constant names are fixed by WordPress, so there is nothing to choose there — only how long
    /// each value is.
    /// </remarks>
    public sealed record WordPressSaltRequest
    {
        /// <summary>Characters in each of the eight values. Between 32 and 128; defaults to 64.</summary>
        public int? Length { get; init; }
    }

    /// <summary>
    /// A generated framework secret, with the figures that describe how hard it is to guess and what
    /// replacing it would cost.
    /// </summary>
    /// <remarks>
    /// <see cref="Value"/> is secret material. Treat this response as sensitive: do not log it, do not cache
    /// it, do not commit it and do not put it in a URL.
    /// </remarks>
    public sealed record FrameworkKeyResponse
    {
        /// <summary>The framework the value was generated for, for example <c>Django</c>.</summary>
        public required string Framework { get; init; }

        /// <summary>
        /// The configuration name the value belongs under, for example <c>SECRET_KEY</c> or <c>APP_KEY</c>.
        /// </summary>
        public required string Setting { get; init; }

        /// <summary>The generated value, including any prefix the framework requires.</summary>
        public required string Value { get; init; }

        /// <summary>Number of characters in the value.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of the generation process in bits: how much guessing an attacker who knows exactly how
        /// the value was made would still have to do. Any prefix the framework requires is excluded, since
        /// it is fixed and adds nothing.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>, for example <c>Very strong</c>.</summary>
        public required string Strength { get; init; }

        /// <summary>
        /// What the value was built from, for example <c>256 random bits, hexadecimal (64 characters)</c>.
        /// Never contains the value itself.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>
        /// The cipher the key was sized for, present only for Laravel. Send this back as
        /// <c>config('app.cipher')</c> if the application is not on the default.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Cipher { get; init; }

        /// <summary>
        /// Advisories about where the value belongs, what depends on it, and what replacing it breaks.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>One named framework secret: the constant it is defined as, and its value.</summary>
    /// <remarks><see cref="Value"/> is secret material; <see cref="Name"/> is fixed by the framework.</remarks>
    public sealed record FrameworkSaltResponse
    {
        /// <summary>The constant this value is defined as, for example <c>AUTH_KEY</c>.</summary>
        public required string Name { get; init; }

        /// <summary>The generated value.</summary>
        public required string Value { get; init; }
    }

    /// <summary>
    /// The set of authentication keys and salts a WordPress installation needs in its <c>wp-config.php</c>.
    /// </summary>
    /// <remarks>
    /// Every value here is secret material, and so is <see cref="Configuration"/>, which contains all of
    /// them. Treat this response as sensitive: do not log it, do not cache it and do not commit it.
    /// </remarks>
    public sealed record WordPressSaltsResponse
    {
        /// <summary>The framework these values were generated for.</summary>
        public required string Framework { get; init; }

        /// <summary>The named values, in the order WordPress lists them.</summary>
        public required IReadOnlyList<FrameworkSaltResponse> Salts { get; init; }

        /// <summary>How many values were generated.</summary>
        public required int Count { get; init; }

        /// <summary>Number of characters in each value.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of one value, in bits. The set as a whole carries this many bits times
        /// <see cref="Count"/>, because the values are drawn independently of one another.
        /// </summary>
        public required double EntropyBitsPerValue { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBitsPerValue"/> for a single value.</summary>
        public required string Strength { get; init; }

        /// <summary>What each value was built from. Never contains any of the values.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// The block to paste into <c>wp-config.php</c>, with every value already quoted, one
        /// <c>define</c> per line.
        /// </summary>
        public required string Configuration { get; init; }

        /// <summary>Advisories about how these values must be handled and what replacing them costs.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
