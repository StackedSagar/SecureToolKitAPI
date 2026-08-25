namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Result of generating a single developer secret: an API key, a JWT signing secret, an OAuth token
    /// or a random string.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Value"/> is secret material. It must never be logged, cached or echoed anywhere other
    /// than the response to the caller that asked for it.
    /// </para>
    /// <para>
    /// The remaining members describe the value without revealing it — <see cref="Composition"/> reports
    /// how many bits went in and how they were rendered, never the characters themselves — so they are
    /// safe to surface in documentation and in API responses.
    /// </para>
    /// </remarks>
    public sealed record GeneratedSecret
    {
        /// <summary>The generated value, including any prefix. Secret.</summary>
        public required string Value { get; init; }

        /// <summary>Number of characters in <see cref="Value"/>.</summary>
        public required int Length { get; init; }

        /// <summary>
        /// Entropy of the generation process in bits: for a value built from random bytes this is eight
        /// bits per byte, and for a value sampled from an alphabet it is the number of characters chosen
        /// times the bits each choice carries. Computed from the process, never by inspecting the value.
        /// </summary>
        public required double EntropyBits { get; init; }

        /// <summary>Plain-language reading of <see cref="EntropyBits"/>, for example <c>Very strong</c>.</summary>
        public required string Strength { get; init; }

        /// <summary>
        /// Description of how the value was built, for example
        /// <c>256 random bits, Base64url encoded (43 characters)</c>. Never contains the value itself.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>
        /// The specific shape that was asked for, when the endpoint has one: the JWT algorithm, the
        /// OAuth token kind or the AI provider whose key format was imitated.
        /// </summary>
        public string? Kind { get; init; }

        /// <summary>Non-fatal advisories, for example how the value should be stored.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// The two random values a relying party needs to start a WebAuthn registration: the challenge the
    /// authenticator signs over, and the user handle that identifies the account to it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The credential ID and the credential public key are produced by the authenticator during
    /// registration and returned by the browser. They cannot be generated on the server, so they are
    /// deliberately absent here.
    /// </para>
    /// <para>
    /// The challenge is single-use and must be remembered server-side for exactly one ceremony. The user
    /// handle is a stable, opaque account identifier and must carry no personal information, which is
    /// why it is random rather than derived from an email address or a user name.
    /// </para>
    /// </remarks>
    public sealed record GeneratedWebAuthnCredential
    {
        /// <summary>
        /// The registration or authentication challenge, Base64url encoded. Not a long-lived secret, but
        /// it must be unpredictable and used only once.
        /// </summary>
        public required string Challenge { get; init; }

        /// <summary>
        /// The user handle, Base64url encoded. Stored against the account and returned to the
        /// authenticator on every ceremony.
        /// </summary>
        public required string UserHandle { get; init; }

        /// <summary>Number of random bytes behind <see cref="Challenge"/>.</summary>
        public required int ChallengeBytes { get; init; }

        /// <summary>Number of random bytes behind <see cref="UserHandle"/>.</summary>
        public required int UserHandleBytes { get; init; }

        /// <summary>How the two values are encoded, so a caller knows what to decode.</summary>
        public required string Format { get; init; }

        /// <summary>Advisories about how these values must be used.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// A VAPID key pair for Web Push, as defined by RFC 8292: an ECDSA P-256 key pair where the public
    /// key is the one a browser is given as the application server key.
    /// </summary>
    /// <remarks>
    /// <see cref="PrivateKey"/> is secret material and must stay on the application server.
    /// <see cref="PublicKey"/> is published to browsers by design and is not secret.
    /// </remarks>
    public sealed record GeneratedVapidKey
    {
        /// <summary>
        /// The uncompressed public point, Base64url encoded — the form Web Push libraries and the
        /// browser's <c>applicationServerKey</c> expect. Public, not secret.
        /// </summary>
        public required string PublicKey { get; init; }

        /// <summary>The private scalar, Base64url encoded, in the form Web Push libraries expect. Secret.</summary>
        public required string PrivateKey { get; init; }

        /// <summary>
        /// The same public key as a PEM-encoded SubjectPublicKeyInfo, for libraries that take a standard
        /// key format rather than the raw VAPID form.
        /// </summary>
        public required string PublicKeyPem { get; init; }

        /// <summary>The same private key as a PEM-encoded PKCS#8 structure. Secret.</summary>
        public required string PrivateKeyPem { get; init; }

        /// <summary>The curve the pair was generated on. VAPID allows only P-256.</summary>
        public required string Curve { get; init; }

        /// <summary>How the raw values are encoded, so a caller knows what to decode.</summary>
        public required string Format { get; init; }

        /// <summary>Advisories about how the pair must be stored and rotated.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }
}
