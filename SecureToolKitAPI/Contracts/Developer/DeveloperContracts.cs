using System.Text.Json.Serialization;

namespace SecureToolKitAPI.Contracts.Developer
{
    /// <summary>
    /// Options for a generated API key. Every member is optional; omit the body entirely for 32 random
    /// bytes rendered as Base64url with no prefix.
    /// </summary>
    /// <remarks>
    /// Options are named rather than numbered — <c>"encoding": "base64url"</c>, not an index — and matching
    /// ignores case, hyphens and underscores. An unrecognised name is reported as a 400 problem response
    /// listing the names that do work, rather than falling back to a default the caller did not ask for.
    /// </remarks>
    public sealed record ApiKeyRequest
    {
        /// <summary>Bytes of randomness. Between 16 and 128; defaults to 32, which is 256 bits.</summary>
        public int? Bytes { get; init; }

        /// <summary>
        /// How the random bytes are rendered: <c>base64url</c>, <c>base64</c>, <c>hex</c>,
        /// <c>hexUpper</c> or <c>base62</c>. Defaults to <c>base64url</c>.
        /// </summary>
        public string? Encoding { get; init; }

        /// <summary>
        /// Text placed in front of the random part, for example <c>sk_live_</c>, so a leaked key can be
        /// recognised by a secret scanner. At most 24 characters, and only letters, digits, hyphens,
        /// underscores and dots. Not secret and not counted towards the entropy. Defaults to none.
        /// </summary>
        public string? Prefix { get; init; }
    }

    /// <summary>Options for a JWT signing secret.</summary>
    public sealed record JwtSecretRequest
    {
        /// <summary>
        /// The HMAC algorithm the secret will sign with: <c>HS256</c>, <c>HS384</c> or <c>HS512</c>.
        /// Defaults to <c>HS256</c>. The size follows from the algorithm, because RFC 7518 requires a key
        /// at least as long as the hash output and a longer one adds nothing.
        /// </summary>
        public string? Algorithm { get; init; }

        /// <summary>
        /// How the secret is rendered. Defaults to <c>base64</c>, which is what most JWT libraries and
        /// configuration files expect.
        /// </summary>
        public string? Encoding { get; init; }
    }

    /// <summary>Options for an opaque OAuth 2.0 value.</summary>
    public sealed record OAuthTokenRequest
    {
        /// <summary>
        /// What the value is for: <c>AccessToken</c>, <c>RefreshToken</c>, <c>ClientSecret</c> or
        /// <c>AuthorizationCode</c>. Defaults to <c>AccessToken</c>. The kind decides the default size and
        /// the advisories returned with it.
        /// </summary>
        public string? Kind { get; init; }

        /// <summary>
        /// Bytes of randomness, between 16 and 128. Omit to use the default for the kind: 32 for an access
        /// token or authorization code, 48 for a client secret, 64 for a refresh token.
        /// </summary>
        public int? Bytes { get; init; }

        /// <summary>
        /// How the value is rendered. Defaults to <c>base64url</c>, which matches the character set
        /// RFC 6750 defines for a bearer token.
        /// </summary>
        public string? Encoding { get; init; }
    }

    /// <summary>Which AI provider's key format to imitate.</summary>
    /// <remarks>
    /// The provider decides the prefix, size and encoding, so there is nothing else to set. Use
    /// <c>POST /api/developer/api-key</c> when you want to choose those yourself.
    /// </remarks>
    public sealed record AiKeyRequest
    {
        /// <summary>
        /// Provider name from <c>GET /api/developer/ai-key/providers</c>, for example <c>openai</c>.
        /// Matched case-insensitively. Defaults to <c>generic</c>.
        /// </summary>
        public string? Provider { get; init; }
    }

    /// <summary>Options for the random values a WebAuthn registration needs.</summary>
    public sealed record WebAuthnRequest
    {
        /// <summary>Bytes of randomness in the challenge. Between 16 and 64; defaults to 32.</summary>
        public int? ChallengeBytes { get; init; }

        /// <summary>
        /// Bytes of randomness in the user handle. Between 16 and 64; defaults to 64, the largest the
        /// WebAuthn specification allows.
        /// </summary>
        public int? UserHandleBytes { get; init; }
    }

    /// <summary>Options for a random string of a requested length.</summary>
    public sealed record RandomStringRequest
    {
        /// <summary>Number of characters. Between 1 and 4096; defaults to 32.</summary>
        public int? Length { get; init; }

        /// <summary>
        /// Which alphabet to sample from: <c>alphanumeric</c>, <c>letters</c>, <c>lowercase</c>,
        /// <c>uppercase</c>, <c>digits</c>, <c>hex</c>, <c>hexUpper</c>, <c>base64url</c> or
        /// <c>custom</c>. Defaults to <c>alphanumeric</c>.
        /// </summary>
        public string? Alphabet { get; init; }

        /// <summary>
        /// The characters to sample from when <see cref="Alphabet"/> is <c>custom</c>. Between 2 and 256
        /// distinct characters, with no whitespace or control characters. Supplying this without asking
        /// for <c>custom</c> is reported as a bad request rather than ignored.
        /// </summary>
        public string? CustomAlphabet { get; init; }
    }

    /// <summary>
    /// A generated developer secret, with the figures that describe how hard it is to guess.
    /// </summary>
    /// <remarks>
    /// <see cref="Value"/> is secret material. Treat this response as sensitive: do not log it, do not
    /// cache it, do not commit it and do not put it in a URL.
    /// </remarks>
    public sealed record DeveloperSecretResponse
    {
        /// <summary>The generated value, including any prefix.</summary>
        public required string Value { get; init; }

        /// <summary>Number of characters in the value.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of the generation process in bits: how much guessing an attacker who knows exactly how
        /// the value was made would still have to do. Higher is better; this is a conservative figure.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>, for example <c>Very strong</c>.</summary>
        public required string Strength { get; init; }

        /// <summary>
        /// What the value was built from, for example <c>256 random bits, Base64url encoded
        /// (43 characters)</c>. Never contains the value itself, and never the prefix — only its length.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>
        /// The specific shape that was asked for, when the endpoint has one: the JWT algorithm, the OAuth
        /// token kind, or the AI provider whose format was imitated.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Kind { get; init; }

        /// <summary>Non-fatal advisories, for example how the value must be stored.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// The random values a relying party needs to start a WebAuthn ceremony.
    /// </summary>
    /// <remarks>
    /// The credential ID and credential public key are produced by the authenticator and returned by the
    /// browser, so they cannot be generated here and are deliberately absent.
    /// </remarks>
    public sealed record WebAuthnCredentialResponse
    {
        /// <summary>The challenge, Base64url encoded. Must be used once and then discarded.</summary>
        public required string Challenge { get; init; }

        /// <summary>The user handle, Base64url encoded. Stored against the account and reused.</summary>
        public required string UserHandle { get; init; }

        /// <summary>Number of random bytes behind the challenge.</summary>
        public required int ChallengeBytes { get; init; }

        /// <summary>Number of random bytes behind the user handle.</summary>
        public required int UserHandleBytes { get; init; }

        /// <summary>How the two values are encoded, so a caller knows what to decode.</summary>
        public required string Format { get; init; }

        /// <summary>Advisories about how these values must be used.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>A VAPID key pair for Web Push.</summary>
    /// <remarks>
    /// The private key and the private PEM are secret material and must stay on the application server.
    /// The public key is published to browsers by design.
    /// </remarks>
    public sealed record VapidKeyResponse
    {
        /// <summary>
        /// The uncompressed public point, Base64url encoded — the value a browser is given as its
        /// <c>applicationServerKey</c>. Public, not secret.
        /// </summary>
        public required string PublicKey { get; init; }

        /// <summary>The private scalar, Base64url encoded, in the form Web Push libraries expect. Secret.</summary>
        public required string PrivateKey { get; init; }

        /// <summary>The same public key as a PEM-encoded SubjectPublicKeyInfo.</summary>
        public required string PublicKeyPem { get; init; }

        /// <summary>The same private key as a PEM-encoded PKCS#8 structure. Secret.</summary>
        public required string PrivateKeyPem { get; init; }

        /// <summary>The curve the pair was generated on. RFC 8292 allows only P-256.</summary>
        public required string Curve { get; init; }

        /// <summary>How the raw values are encoded, so a caller knows what to decode.</summary>
        public required string Format { get; init; }

        /// <summary>Advisories about how the pair must be stored and rotated.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>An AI provider whose API key format this API can imitate.</summary>
    public sealed record AiKeyProviderResponse
    {
        /// <summary>Identifier to send as <c>provider</c>, for example <c>openai</c>.</summary>
        public required string Name { get; init; }

        /// <summary>The provider's product name, as it is usually written.</summary>
        public required string DisplayName { get; init; }

        /// <summary>What the key looks like, and why those options were chosen.</summary>
        public required string Description { get; init; }

        /// <summary>Bytes of randomness a key for this provider carries.</summary>
        public required int Bytes { get; init; }

        /// <summary>The prefix keys for this provider carry, or an empty string when there is none.</summary>
        public required string Prefix { get; init; }

        /// <summary>
        /// Advisories that apply to every key generated for this provider, starting with the reminder that
        /// the value only imitates the format and is not a working credential.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
