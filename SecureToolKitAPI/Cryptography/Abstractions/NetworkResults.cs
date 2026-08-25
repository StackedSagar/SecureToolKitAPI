namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Result of generating an SSH key pair: the public half in the form an <c>authorized_keys</c> file
    /// takes, the private half in PEM, and the fingerprint that ties the two together.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PrivateKey"/> is the only secret here and it is the whole of the secret. It must never be
    /// logged, cached, written to disk by this API or echoed anywhere other than the response to the caller
    /// that asked for it. Everything else in this record is published by design: a public key is meant to be
    /// copied onto servers, and a fingerprint is meant to be read out loud.
    /// </para>
    /// <para>
    /// There is no entropy figure. An SSH key is not a sampled string, so counting the bits that went into it
    /// would describe the generation and not the key; <see cref="SecurityStrengthBits"/> reports the strength
    /// the key actually has instead, which is the number worth comparing against a symmetric key.
    /// </para>
    /// </remarks>
    public sealed record GeneratedSshKey
    {
        /// <summary>The algorithm spelled as <c>ssh-keygen -t</c> spells it, for example <c>rsa</c>.</summary>
        public required string Algorithm { get; init; }

        /// <summary>
        /// The key type name that starts the public key line, for example <c>ssh-rsa</c> or
        /// <c>ecdsa-sha2-nistp256</c>. This is what a server matches against its accepted key types.
        /// </summary>
        public required string KeyType { get; init; }

        /// <summary>Size of the key in bits; for ECDSA, the size of the curve's field.</summary>
        public required int Bits { get; init; }

        /// <summary>
        /// The symmetric key length this key is comparable to, in bits, from NIST SP 800-57. Compare this
        /// with a symmetric key size rather than comparing <see cref="Bits"/>.
        /// </summary>
        public required int SecurityStrengthBits { get; init; }

        /// <summary>
        /// The public key as a single <c>authorized_keys</c> line: key type, Base64 blob and comment. Not
        /// secret — this is the half that is meant to be copied onto servers.
        /// </summary>
        public required string PublicKey { get; init; }

        /// <summary>
        /// The private key in PEM. Secret, and unencrypted, so it is only as protected as wherever the
        /// caller puts it next.
        /// </summary>
        public required string PrivateKey { get; init; }

        /// <summary>
        /// The format <see cref="PrivateKey"/> is written in, so a caller knows what they are holding without
        /// having to parse it.
        /// </summary>
        public required string PrivateKeyFormat { get; init; }

        /// <summary>
        /// The <c>SHA256:</c> fingerprint of the public key, the same string <c>ssh-keygen -lf</c> prints.
        /// Not secret: it is a hash of a public value, which is what makes it usable for confirming out of
        /// band that the key on the server is this key.
        /// </summary>
        public required string Fingerprint { get; init; }

        /// <summary>The comment on the public key line, or <c>null</c> when none was asked for. Not secret.</summary>
        public string? Comment { get; init; }

        /// <summary>
        /// Description of what was generated, for example <c>RSA 3072-bit key pair</c>. Never contains key
        /// material.
        /// </summary>
        public required string Composition { get; init; }

        /// <summary>Advisories about how the private key must be handled and where it is accepted.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// One entry in the catalogue of SSH key types this API will generate. Contains no key material and
    /// nothing that varies between requests.
    /// </summary>
    /// <remarks>
    /// The catalogue exists so a caller can discover the accepted combinations rather than guessing at them
    /// and reading error messages, which is why it is safe to serve over GET while key generation is not.
    /// </remarks>
    public sealed record SshKeyTypeInfo
    {
        /// <summary>The algorithm to ask for, spelled as <c>ssh-keygen -t</c> spells it.</summary>
        public required string Algorithm { get; init; }

        /// <summary>Size in bits to ask for.</summary>
        public required int Bits { get; init; }

        /// <summary>The key type name a key generated with these options will carry.</summary>
        public required string KeyType { get; init; }

        /// <summary>The comparable symmetric strength in bits, from NIST SP 800-57.</summary>
        public required int SecurityStrengthBits { get; init; }

        /// <summary>Whether these are the options used when the caller asks for nothing in particular.</summary>
        public required bool IsDefault { get; init; }

        /// <summary>What this combination is suited to, in plain language.</summary>
        public required string Notes { get; init; }
    }
}
