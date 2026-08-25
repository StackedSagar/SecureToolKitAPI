using System.Text.Json.Serialization;

namespace SecureToolKitAPI.Contracts.Network
{
    /// <summary>
    /// Options for an SSH key pair. Every member is optional; omit the body entirely for an RSA 3072-bit key
    /// with no comment.
    /// </summary>
    /// <remarks>
    /// There is no passphrase option. Encrypting an SSH private key means writing OpenSSH's own key container,
    /// which this API does not assemble by hand, so the key comes back unencrypted and the response says so.
    /// Add a passphrase with <c>ssh-keygen -p</c> once the key is on disk.
    /// </remarks>
    public sealed record SshKeyRequest
    {
        /// <summary>
        /// The signature algorithm: <c>rsa</c> or <c>ecdsa</c>, spelled as <c>ssh-keygen -t</c> spells it.
        /// Matching ignores case, hyphens and underscores. Defaults to <c>rsa</c>, the type most likely to be
        /// accepted by whatever is at the other end. <c>ed25519</c> is not available and is reported as
        /// unsupported rather than substituted.
        /// </summary>
        public string? Algorithm { get; init; }

        /// <summary>
        /// Size in bits: 2048, 3072 or 4096 for RSA, or 256, 384 or 521 for ECDSA, where it selects the NIST
        /// curve. Defaults to 3072 for RSA and 256 for ECDSA. Call <c>GET /api/network/ssh/key-types</c> for
        /// the full list.
        /// </summary>
        public int? Bits { get; init; }

        /// <summary>
        /// The comment that trails the public key, conventionally identifying whose key it is and where it
        /// lives, such as <c>deploy@build-agent</c>. Up to 128 printable ASCII characters; omit it for a
        /// public key line with no comment. Never secret.
        /// </summary>
        public string? Comment { get; init; }
    }

    /// <summary>
    /// A generated SSH key pair: the public half ready to append to <c>authorized_keys</c>, the private half
    /// in PEM, and the fingerprint that ties them together.
    /// </summary>
    /// <remarks>
    /// <see cref="PrivateKey"/> is secret material and the rest of this response is not. Treat the response as
    /// sensitive on that account: do not log it, do not cache it and do not commit it. The public key,
    /// fingerprint and comment are all meant to be shared.
    /// </remarks>
    public sealed record SshKeyResponse
    {
        /// <summary>The algorithm used, spelled as <c>ssh-keygen -t</c> spells it.</summary>
        public required string Algorithm { get; init; }

        /// <summary>
        /// The key type name that starts the public key line, for example <c>ssh-rsa</c> or
        /// <c>ecdsa-sha2-nistp256</c>. This is what a host matches against its accepted key types.
        /// </summary>
        public required string KeyType { get; init; }

        /// <summary>Size of the key in bits; for ECDSA, the size of the curve's field.</summary>
        public required int Bits { get; init; }

        /// <summary>
        /// The symmetric key length this key is comparable to, in bits, from NIST SP 800-57. Compare this
        /// against a symmetric key size rather than comparing <see cref="Bits"/>: a 3072-bit RSA key and a
        /// 256-bit ECDSA key both sit at the 128-bit level.
        /// </summary>
        public required int SecurityStrengthBits { get; init; }

        /// <summary>
        /// The public key as a single line, ready to append to <c>~/.ssh/authorized_keys</c> on the machine
        /// you want to reach. Not secret.
        /// </summary>
        public required string PublicKey { get; init; }

        /// <summary>
        /// The private key in PEM, unencrypted. Save it with owner-only permissions and never send it
        /// anywhere.
        /// </summary>
        public required string PrivateKey { get; init; }

        /// <summary>The format the private key is written in.</summary>
        public required string PrivateKeyFormat { get; init; }

        /// <summary>
        /// The <c>SHA256:</c> fingerprint of the public key — the same string <c>ssh-keygen -lf</c> prints.
        /// Compare it after installing the public key to confirm the host has this key and not a substitute.
        /// </summary>
        public required string Fingerprint { get; init; }

        /// <summary>The comment on the public key line, omitted when none was asked for.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Comment { get; init; }

        /// <summary>What was generated. Never contains key material.</summary>
        public required string Composition { get; init; }

        /// <summary>
        /// Advisories about handling the private key, where the public key goes, and what this API cannot do
        /// for you.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// One SSH algorithm and size combination this API will generate. Contains no key material.
    /// </summary>
    public sealed record SshKeyTypeResponse
    {
        /// <summary>The value to send as <c>algorithm</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>The value to send as <c>bits</c>.</summary>
        public required int Bits { get; init; }

        /// <summary>The key type name a key generated with these options will carry.</summary>
        public required string KeyType { get; init; }

        /// <summary>The comparable symmetric strength in bits, from NIST SP 800-57.</summary>
        public required int SecurityStrengthBits { get; init; }

        /// <summary>Whether these are the options used when nothing is asked for.</summary>
        public required bool IsDefault { get; init; }

        /// <summary>What this combination is suited to.</summary>
        public required string Notes { get; init; }
    }
}
