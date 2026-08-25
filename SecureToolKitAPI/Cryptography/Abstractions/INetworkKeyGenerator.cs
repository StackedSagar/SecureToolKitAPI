namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates the key material used to authenticate to remote machines, and describes the combinations it
    /// will generate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only SSH keys are implemented. PGP and WireGuard belong to the same functional group and are not here:
    /// a PGP key is a packet-format problem rather than a key-generation one, and WireGuard needs an X25519
    /// key pair, which .NET does not expose. Both are omitted rather than approximated, because a key of the
    /// wrong shape is worse than no key.
    /// </para>
    /// <para>
    /// Implementations are expected to be stateless and safe to share, and must not retain generated private
    /// keys after returning them.
    /// </para>
    /// </remarks>
    public interface INetworkKeyGenerator
    {
        /// <summary>Generates an SSH key pair.</summary>
        /// <param name="spec">Options for the key. Validated before any key is generated.</param>
        /// <returns>
        /// The key pair, whose private half is secret material and must not be logged or retained.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are unsupported or unusable.</exception>
        GeneratedSshKey GenerateSshKey(SshKeySpec spec);

        /// <summary>Lists the SSH algorithm and size combinations this API will generate.</summary>
        /// <returns>The catalogue, in a stable order. Contains no key material.</returns>
        IReadOnlyList<SshKeyTypeInfo> SshKeyTypes();
    }
}
