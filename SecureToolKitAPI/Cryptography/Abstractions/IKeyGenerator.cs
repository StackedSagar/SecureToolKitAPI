namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates key material for a single cryptographic method using
    /// cryptographically secure randomness provided by .NET.
    /// </summary>
    public interface IKeyGenerator : ICryptographicMethod
    {
        /// <summary>Key sizes, in bits, accepted by <see cref="Generate"/>.</summary>
        IReadOnlyCollection<int> SupportedKeySizes { get; }

        /// <summary>Key size, in bits, used when the caller does not specify one.</summary>
        int DefaultKeySize { get; }

        /// <summary>
        /// Generates new key material.
        /// </summary>
        /// <param name="keySizeBits">Requested key size in bits, or <c>null</c> to use <see cref="DefaultKeySize"/>.</param>
        /// <exception cref="CryptographicRequestException">The requested key size is not supported.</exception>
        GeneratedKey Generate(int? keySizeBits);
    }
}
