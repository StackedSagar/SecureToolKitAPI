using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>
    /// Resolves a cryptographic method from the identifier supplied by the caller. One registry is
    /// created per method family, so adding a method only means registering another implementation.
    /// </summary>
    /// <typeparam name="TMethod">Method family, for example <see cref="IKeyGenerator"/>.</typeparam>
    public sealed class CryptographicMethodRegistry<TMethod> where TMethod : ICryptographicMethod
    {
        private readonly Dictionary<string, TMethod> _byIdentifier;
        private readonly List<TMethod> _methods;

        /// <summary>
        /// Indexes the supplied methods by canonical name and by alias.
        /// </summary>
        /// <param name="methods">Registered implementations, supplied by dependency injection.</param>
        /// <exception cref="InvalidOperationException">
        /// Two methods claim the same identifier. This is a wiring mistake, not a caller error, so it
        /// fails at startup rather than surfacing as a confusing runtime response.
        /// </exception>
        public CryptographicMethodRegistry(IEnumerable<TMethod> methods)
        {
            ArgumentNullException.ThrowIfNull(methods);

            _methods = methods.OrderBy(method => method.Name, StringComparer.OrdinalIgnoreCase).ToList();
            _byIdentifier = new Dictionary<string, TMethod>(StringComparer.OrdinalIgnoreCase);

            foreach (var method in _methods)
            {
                Index(method.Name, method);

                foreach (var alias in method.Aliases)
                {
                    Index(alias, method);
                }
            }
        }

        /// <summary>All registered methods, ordered by canonical name.</summary>
        public IReadOnlyList<TMethod> Methods => _methods;

        /// <summary>Canonical names of all registered methods.</summary>
        public IReadOnlyList<string> SupportedNames => _methods.Select(method => method.Name).ToList();

        /// <summary>
        /// Resolves a method by canonical name or alias, ignoring case and surrounding whitespace.
        /// </summary>
        /// <param name="method">Identifier supplied by the caller.</param>
        /// <exception cref="CryptographicRequestException">The identifier is missing or not supported.</exception>
        public TMethod Resolve(string? method)
        {
            if (string.IsNullOrWhiteSpace(method))
            {
                throw new CryptographicRequestException(
                    $"A method is required. Supported methods: {string.Join(", ", SupportedNames)}.");
            }

            if (_byIdentifier.TryGetValue(method.Trim(), out var resolved))
            {
                return resolved;
            }

            throw new CryptographicRequestException(
                $"Unsupported method '{method.Trim()}'. Supported methods: {string.Join(", ", SupportedNames)}.");
        }

        /// <summary>Attempts to resolve a method without throwing.</summary>
        public bool TryResolve(string? method, out TMethod? resolved)
        {
            resolved = default;

            if (string.IsNullOrWhiteSpace(method))
            {
                return false;
            }

            if (_byIdentifier.TryGetValue(method.Trim(), out var found))
            {
                resolved = found;
                return true;
            }

            return false;
        }

        private void Index(string identifier, TMethod method)
        {
            if (string.IsNullOrWhiteSpace(identifier))
            {
                throw new InvalidOperationException(
                    $"Method '{method.GetType().Name}' declares a blank identifier.");
            }

            if (!_byIdentifier.TryAdd(identifier, method))
            {
                throw new InvalidOperationException(
                    $"Identifier '{identifier}' is claimed by more than one {typeof(TMethod).Name} implementation.");
            }
        }
    }
}
