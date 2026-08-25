using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.KeyGeneration
{
    /// <summary>
    /// Shared key-size validation for key generators so every method rejects unsupported
    /// sizes consistently before any key material is produced.
    /// </summary>
    public abstract class KeyGeneratorBase : IKeyGenerator
    {
        /// <inheritdoc />
        public abstract string Name { get; }

        /// <inheritdoc />
        public virtual IReadOnlyCollection<string> Aliases => Array.Empty<string>();

        /// <inheritdoc />
        public abstract string Description { get; }

        /// <inheritdoc />
        public abstract IReadOnlyCollection<int> SupportedKeySizes { get; }

        /// <inheritdoc />
        public abstract int DefaultKeySize { get; }

        /// <inheritdoc />
        public GeneratedKey Generate(int? keySizeBits)
        {
            var requested = keySizeBits ?? DefaultKeySize;

            if (!SupportedKeySizes.Contains(requested))
            {
                throw new CryptographicRequestException(
                    $"Invalid key size {requested} for '{Name}'. Supported sizes are: {string.Join(", ", SupportedKeySizes)}.");
            }

            return GenerateCore(requested);
        }

        /// <summary>Produces key material for an already validated key size.</summary>
        /// <param name="keySizeBits">Validated key size in bits.</param>
        protected abstract GeneratedKey GenerateCore(int keySizeBits);
    }
}
