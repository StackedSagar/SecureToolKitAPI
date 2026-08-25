using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Network
{
    /// <summary>
    /// Generates SSH key pairs: an RSA or ECDSA key from the platform's own implementation, written out in
    /// the two forms OpenSSH reads — a single-line public key and a PEM private key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The keys themselves come from <see cref="RSA.Create(int)"/> and <see cref="ECDsa.Create(ECCurve)"/>,
    /// so the prime generation, the curve arithmetic and the randomness are all the platform's. What this
    /// class adds is the arrangement of the public half into the byte order OpenSSH expects, which
    /// <see cref="SshWireFormat"/> does, and the advisory text that goes with a private key.
    /// </para>
    /// <para>
    /// The private key is exported as PKCS#8 PEM rather than in OpenSSH's own private key format. Both are
    /// accepted by <c>ssh-keygen</c> and by <c>ssh</c> itself; the difference is that the OpenSSH format has
    /// a container this API would have to assemble by hand, and PKCS#8 has one .NET already writes. It is
    /// unencrypted either way, which the warnings say out loud.
    /// </para>
    /// <para>
    /// The class is stateless and safe to share as a singleton. No key is retained after it is returned: the
    /// key object is disposed on the way out, and the strings belong to the caller.
    /// </para>
    /// </remarks>
    public sealed class NetworkKeyGenerator : INetworkKeyGenerator
    {
        /// <summary>How <see cref="GeneratedSshKey.PrivateKey"/> is written.</summary>
        private const string PrivateKeyFormat = "Unencrypted PKCS#8 private key in PEM.";

        /// <summary>
        /// The catalogue, built once and validated as it is built so an unsupported combination cannot be
        /// advertised.
        /// </summary>
        private static readonly SshKeyTypeInfo[] KeyTypes = BuildKeyTypes();

        /// <inheritdoc />
        public GeneratedSshKey GenerateSshKey(SshKeySpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            // A curve name is present for exactly the ECDSA specs, so this both selects the algorithm and
            // hands the curve over without a second null check.
            return spec.CurveName is { } curveName
                ? GenerateEcdsa(spec, curveName)
                : GenerateRsa(spec);
        }

        /// <inheritdoc />
        public IReadOnlyList<SshKeyTypeInfo> SshKeyTypes() => KeyTypes;

        /// <summary>Generates an RSA key pair and writes both halves.</summary>
        /// <param name="spec">Validated options.</param>
        private static GeneratedSshKey GenerateRsa(SshKeySpec spec)
        {
            using var rsa = RSA.Create(spec.KeySizeBits);

            var blob = SshWireFormat.RsaPublicKeyBlob(rsa.ExportParameters(includePrivateParameters: false));

            return Describe(
                spec,
                blob,
                rsa.ExportPkcs8PrivateKeyPem(),
                [
                    "The key type on the public key line is ssh-rsa, which is the name of the key format and "
                    + "not the name of a signature algorithm. Current OpenSSH signs with rsa-sha2-256 or "
                    + "rsa-sha2-512 using this same key, so the deprecation notices you may have read about "
                    + "\"ssh-rsa\" refer to the old SHA-1 signature and not to this key.",
                    spec.KeySizeBits == 2048
                        ? "2048 bits sits at the 112-bit security level rather than 128. It is here because a "
                          + "good deal of deployed hardware accepts nothing larger; if nothing in the path "
                          + "requires it, generate 3072 instead."
                        : "RSA keys are large, so the handshake is slower and the authorized_keys line is long. "
                          + "An ECDSA key on nistp256 reaches the same 128-bit level in a fraction of the size, "
                          + "where the server accepts it."
                ]);
        }

        /// <summary>Generates an ECDSA key pair and writes both halves.</summary>
        /// <param name="spec">Validated options.</param>
        /// <param name="curveName">The SSH curve identifier, for example <c>nistp256</c>.</param>
        private static GeneratedSshKey GenerateEcdsa(SshKeySpec spec, string curveName)
        {
            using var ecdsa = ECDsa.Create(EcCurves.FromKeySize(spec.KeySizeBits));

            // Only the public point is needed, so the parameters are exported without the private half rather
            // than exported whole and narrowed afterwards.
            var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            var blob = SshWireFormat.EcdsaPublicKeyBlob(curveName, parameters.Q);

            return Describe(
                spec,
                blob,
                ecdsa.ExportPkcs8PrivateKeyPem(),
                [
                    $"This is an ECDSA key on {curveName}. A server restricted to RSA keys, whether by policy "
                    + "or by age, will refuse it — check the host's accepted key types before replacing a "
                    + "working RSA key with this one.",
                    spec.KeySizeBits == 521
                        ? "nistp521 is the least widely deployed of the three SSH curves. It is standard, but "
                          + "expect to meet clients and appliances that only implement nistp256."
                        : "The whole public key fits comfortably on one line, which is part of why ECDSA keys "
                          + "are easier to manage in authorized_keys files than RSA keys of matching strength."
                ]);
        }

        /// <summary>
        /// Assembles the result: the public key line, the fingerprint, and the advisories that apply to any
        /// SSH private key regardless of algorithm.
        /// </summary>
        /// <param name="spec">Validated options.</param>
        /// <param name="blob">The public key blob.</param>
        /// <param name="privateKeyPem">The private key in PEM. Secret.</param>
        /// <param name="algorithmWarnings">Advisories specific to the algorithm and size chosen.</param>
        /// <remarks>
        /// The shared warnings come first because they are the ones that matter most: an SSH private key that
        /// travelled over a network is in a different position from one that never left the machine that will
        /// use it, and a caller deserves to be told that by the API that just generated it.
        /// </remarks>
        private static GeneratedSshKey Describe(
            SshKeySpec spec,
            byte[] blob,
            string privateKeyPem,
            IReadOnlyList<string> algorithmWarnings)
        {
            string[] shared =
            [
                "This private key was generated on a server and sent to you over the network. A key that is "
                + "meant to protect production access is better generated where it will be used, with "
                + "ssh-keygen, so that the private half never crosses a wire at all. Treat anything generated "
                + "here as suitable for development, throwaway hosts and automation you are willing to "
                + "re-key.",
                "The private key is not encrypted. Anyone who reads it can authenticate as you wherever the "
                + "public half is installed. Save it with owner-only permissions — ssh refuses to use a key "
                + "file others can read — and add a passphrase with ssh-keygen -p once it is on disk.",
                "Only the public key goes on the remote machine, appended to ~/.ssh/authorized_keys as the "
                + "single line returned here. Never send the private key to a server, paste it into a form, "
                + "or commit it: a key in version control has to be replaced everywhere it was installed.",
                "Check the fingerprint after installing the public key. ssh-keygen -lf on the server must "
                + "print the same SHA256 value returned here, which is what tells you the key on the host is "
                + "the key you generated and not one someone else substituted.",
                "OpenSSH's own default key type is ed25519, which this API does not offer: .NET exposes no "
                + "ed25519 primitive to call, and implementing one here rather than calling a vetted "
                + "implementation would be the wrong trade. Use ssh-keygen -t ed25519 directly if that is "
                + "what you need."
            ];

            return new GeneratedSshKey
            {
                Algorithm = spec.AlgorithmName,
                KeyType = spec.KeyTypeName,
                Bits = spec.KeySizeBits,
                SecurityStrengthBits = spec.SecurityStrengthBits,
                PublicKey = SshWireFormat.AuthorizedKeysLine(
                    spec.KeyTypeName,
                    blob,
                    spec.NormalizedComment),
                PrivateKey = privateKeyPem,
                PrivateKeyFormat = PrivateKeyFormat,
                Fingerprint = SshWireFormat.Fingerprint(blob),
                Comment = spec.NormalizedComment,
                Composition = spec.Describe(),
                Warnings = [.. shared, .. algorithmWarnings]
            };
        }

        /// <summary>
        /// Builds the catalogue from the supported sizes, validating each entry so a combination this API
        /// would reject can never appear in the listing.
        /// </summary>
        private static SshKeyTypeInfo[] BuildKeyTypes()
        {
            var entries = new List<SshKeyTypeInfo>();

            foreach (var algorithm in Enum.GetValues<SshKeyAlgorithm>())
            {
                foreach (var bits in SshKeySpec.SupportedSizes(algorithm))
                {
                    var spec = new SshKeySpec { Algorithm = algorithm, Bits = bits };

                    // Validating here means a typo in the size tables fails at startup rather than being
                    // advertised to callers and rejected when they act on it.
                    spec.Validate();

                    entries.Add(new SshKeyTypeInfo
                    {
                        Algorithm = spec.AlgorithmName,
                        Bits = bits,
                        KeyType = spec.KeyTypeName,
                        SecurityStrengthBits = spec.SecurityStrengthBits,
                        IsDefault = algorithm is SshKeyAlgorithm.Rsa
                                    && bits == SshKeySpec.DefaultSize(SshKeyAlgorithm.Rsa),
                        Notes = Notes(algorithm, bits)
                    });
                }
            }

            return [.. entries];
        }

        /// <summary>What a given combination is suited to, in plain language.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="bits">The size in bits.</param>
        private static string Notes(SshKeyAlgorithm algorithm, int bits) => (algorithm, bits) switch
        {
            (SshKeyAlgorithm.Rsa, 2048) =>
                "Widest compatibility, including older appliances. The 112-bit level, so choose 3072 unless "
                + "something in the path requires 2048.",
            (SshKeyAlgorithm.Rsa, 3072) =>
                "The default. Accepted by every current OpenSSH and at the 128-bit level.",
            (SshKeyAlgorithm.Rsa, 4096) =>
                "Margin above 3072 rather than a higher tabulated strength, at the cost of slower generation "
                + "and a longer authorized_keys line.",
            (SshKeyAlgorithm.Ecdsa, 256) =>
                "The same 128-bit level as RSA 3072 in a fraction of the size. Refused by hosts configured "
                + "for RSA only.",
            (SshKeyAlgorithm.Ecdsa, 384) =>
                "The 192-bit level, and still short. A reasonable choice where policy asks for more than 128.",
            (SshKeyAlgorithm.Ecdsa, 521) =>
                "The 256-bit level. Standard but the least widely implemented of the three SSH curves.",
            _ => "Supported."
        };
    }
}
