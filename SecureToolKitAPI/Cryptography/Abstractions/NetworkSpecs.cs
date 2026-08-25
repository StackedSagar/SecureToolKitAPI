using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>The signature algorithms this API will generate an SSH key for.</summary>
    /// <remarks>
    /// <para>
    /// These are the two spellings <c>ssh-keygen -t</c> accepts that rest on primitives
    /// <see cref="System.Security.Cryptography"/> provides. Both are accepted by every current OpenSSH
    /// server.
    /// </para>
    /// <para>
    /// Ed25519 is deliberately absent. It is the key type OpenSSH now generates by default and would be the
    /// natural first choice, but .NET exposes no Ed25519 primitive that this project can call, and
    /// implementing one here would break the rule that cryptographic primitives are never written by hand.
    /// An algorithm that is missing is a smaller problem than an algorithm that is homemade.
    /// </para>
    /// </remarks>
    public enum SshKeyAlgorithm
    {
        /// <summary>RSA, as <c>ssh-rsa</c>. The most widely accepted key type, including by older servers.</summary>
        Rsa,

        /// <summary>ECDSA on a NIST curve, as <c>ecdsa-sha2-nistp256</c> and its larger siblings.</summary>
        Ecdsa
    }

    /// <summary>
    /// Options for an SSH key pair: the algorithm, its size, and the comment that trails the public key in
    /// an <c>authorized_keys</c> file.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The defaults are RSA at 3072 bits. RSA is chosen over ECDSA for the default because it is the type
    /// most likely to be accepted by whatever is at the other end — appliances, managed Git hosts and older
    /// servers included — and 3072 bits is the size NIST puts at the 128-bit security level, matching what
    /// the rest of this API generates.
    /// </para>
    /// <para>
    /// There is no option for a passphrase on the private key. Encrypting a private key means deriving a key
    /// from a passphrase and wrapping the key with it, and the OpenSSH private key format does that with its
    /// own container that .NET does not write. Rather than assemble that container by hand, this API returns
    /// the key unencrypted and says so plainly in its warnings, which is the honest of the two options.
    /// </para>
    /// </remarks>
    public sealed record SshKeySpec
    {
        /// <summary>RSA sizes this API will generate, smallest first.</summary>
        /// <remarks>
        /// 1024 is absent because it is broken for this purpose, and 2048 is kept because a great deal of
        /// deployed hardware accepts nothing larger.
        /// </remarks>
        private static readonly int[] RsaSizes = [2048, 3072, 4096];

        /// <summary>ECDSA curve sizes this API will generate, smallest first.</summary>
        /// <remarks>
        /// These are the three curves RFC 5656 defines for SSH — P-256, P-384 and P-521 — and the only ones
        /// OpenSSH implements. 521 is not a typo for 512: that is the size of the field the curve is over.
        /// </remarks>
        private static readonly int[] EcdsaSizes = [256, 384, 521];

        /// <summary>Longest comment this API will put on a public key.</summary>
        public const int MaximumCommentLength = 128;

        /// <summary>The signature algorithm. Defaults to <see cref="SshKeyAlgorithm.Rsa"/>.</summary>
        public SshKeyAlgorithm Algorithm { get; init; } = SshKeyAlgorithm.Rsa;

        /// <summary>
        /// Size of the key in bits, or <c>null</c> to take the default for the chosen algorithm. For ECDSA
        /// this selects the curve rather than a modulus length.
        /// </summary>
        public int? Bits { get; init; }

        /// <summary>
        /// The comment that trails the public key, conventionally something identifying whose key it is and
        /// where it lives, such as <c>deploy@build-agent</c>. Optional, and never secret.
        /// </summary>
        public string? Comment { get; init; }

        /// <summary>The size that will actually be used, once the default has been applied.</summary>
        public int KeySizeBits => Bits ?? DefaultSize(Algorithm);

        /// <summary>The comment with surrounding whitespace removed, or <c>null</c> when there is none.</summary>
        public string? NormalizedComment =>
            string.IsNullOrWhiteSpace(Comment) ? null : Comment.Trim();

        /// <summary>The algorithm spelled the way <c>ssh-keygen -t</c> spells it.</summary>
        public string AlgorithmName => Algorithm is SshKeyAlgorithm.Ecdsa ? "ecdsa" : "rsa";

        /// <summary>
        /// The SSH curve identifier for an ECDSA key, for example <c>nistp256</c>, or <c>null</c> for RSA,
        /// which has no curve.
        /// </summary>
        public string? CurveName =>
            Algorithm is SshKeyAlgorithm.Ecdsa ? $"nistp{KeySizeBits}" : null;

        /// <summary>
        /// The key type name that appears at the start of the public key line and inside the key blob, for
        /// example <c>ssh-rsa</c> or <c>ecdsa-sha2-nistp384</c>.
        /// </summary>
        public string KeyTypeName => CurveName is null
            ? SshWireFormat.RsaKeyType
            : SshWireFormat.EcdsaKeyType(CurveName);

        /// <summary>
        /// The symmetric key length this key is comparable to, in bits, from the equivalence table in NIST
        /// SP 800-57.
        /// </summary>
        /// <remarks>
        /// This is the number worth comparing against a 128-bit or 256-bit symmetric key, and
        /// <see cref="KeySizeBits"/> is not: a 3072-bit RSA key and a 256-bit P-256 key both sit at the
        /// 128-bit level despite one number being twelve times the other. RSA at 4096 bits is reported at
        /// that same 128-bit level because it is the highest level NIST's table assigns it — the next level
        /// up, 192 bits, corresponds to RSA at 7680 bits — so the extra size buys margin rather than a
        /// higher tabulated strength.
        /// </remarks>
        public int SecurityStrengthBits => Algorithm is SshKeyAlgorithm.Ecdsa
            ? KeySizeBits switch { 521 => 256, 384 => 192, _ => 128 }
            : KeySizeBits switch { 2048 => 112, _ => 128 };

        /// <summary>Sizes this API will generate for a given algorithm.</summary>
        /// <param name="algorithm">The algorithm to list sizes for.</param>
        public static IReadOnlyList<int> SupportedSizes(SshKeyAlgorithm algorithm) =>
            algorithm is SshKeyAlgorithm.Ecdsa ? EcdsaSizes : RsaSizes;

        /// <summary>The size used when the caller does not ask for one.</summary>
        /// <param name="algorithm">The algorithm to give the default for.</param>
        public static int DefaultSize(SshKeyAlgorithm algorithm) =>
            algorithm is SshKeyAlgorithm.Ecdsa ? 256 : 3072;

        /// <summary>Validates the options before any key is generated.</summary>
        /// <exception cref="CryptographicRequestException">An option is unsupported or unusable.</exception>
        public void Validate()
        {
            if (!Enum.IsDefined(Algorithm))
            {
                throw new CryptographicRequestException("The requested key algorithm is not supported.");
            }

            var supported = SupportedSizes(Algorithm);

            if (!supported.Contains(KeySizeBits))
            {
                throw new CryptographicRequestException(
                    $"Unsupported key size {KeySizeBits} for an {AlgorithmName} key. Supported sizes are: "
                    + $"{string.Join(", ", supported)}.");
            }

            ValidateComment();
        }

        /// <summary>Describes the key that will be generated, for the response.</summary>
        /// <returns>A caller-safe description; no key is generated and none is revealed.</returns>
        public string Describe() => CurveName is null
            ? $"RSA {KeySizeBits}-bit key pair, comparable to a {SecurityStrengthBits}-bit symmetric key"
            : $"ECDSA key pair on {CurveName} (NIST P-{KeySizeBits}), comparable to a "
              + $"{SecurityStrengthBits}-bit symmetric key";

        /// <summary>
        /// Rejects a comment that could not sit safely on a single <c>authorized_keys</c> line.
        /// </summary>
        /// <remarks>
        /// A line break is the case that matters: the public key is one line, and a comment carrying a
        /// newline would end that line and let whatever followed be read as a second authorized key. The
        /// remaining restriction to printable ASCII is a matter of predictability rather than safety, since
        /// the comment travels through shells, editors and log files on its way to a server.
        /// </remarks>
        private void ValidateComment()
        {
            var comment = NormalizedComment;

            if (comment is null)
            {
                return;
            }

            if (comment.Length > MaximumCommentLength)
            {
                throw new CryptographicRequestException(
                    $"The comment must be {MaximumCommentLength} characters or fewer.");
            }

            foreach (var character in comment)
            {
                if (character is < ' ' or > '~')
                {
                    throw new CryptographicRequestException(
                        "The comment must contain only printable ASCII characters. A line break or control "
                        + "character would split the single line a public key occupies.");
                }
            }
        }
    }

    /// <summary>
    /// Reads the caller-facing spelling of the network key options and turns it into the corresponding
    /// option, so an unknown value is reported as a bad request rather than silently falling back to a
    /// default.
    /// </summary>
    /// <remarks>
    /// Matching ignores case, hyphens, underscores and spaces. An omitted value means "use the default".
    /// </remarks>
    public static class NetworkOptions
    {
        /// <summary>Resolves an SSH key algorithm name such as <c>rsa</c> or <c>ecdsa</c>.</summary>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <returns>The resolved algorithm.</returns>
        /// <exception cref="CryptographicRequestException">The name is not a supported algorithm.</exception>
        /// <remarks>
        /// <c>ed25519</c> lands here as an unsupported name, which is the intended answer: it is better to
        /// say the algorithm is not available than to quietly hand back an RSA key to a caller who asked for
        /// something else.
        /// </remarks>
        public static SshKeyAlgorithm ParseSshAlgorithm(string? value) =>
            OptionName.Parse(value, SshKeyAlgorithm.Rsa, "key algorithm");
    }
}
