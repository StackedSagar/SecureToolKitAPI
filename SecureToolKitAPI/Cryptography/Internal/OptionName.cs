using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Resolves the caller-facing spelling of an option into the option itself, so an unknown value is
    /// reported as a bad request rather than silently falling back to a default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Matching ignores case, hyphens, underscores and spaces, so <c>base64url</c>, <c>Base64-Url</c> and
    /// <c>BASE64_URL</c> all resolve to the same option. An omitted value means "use the default".
    /// </para>
    /// <para>
    /// This lives here rather than beside any one set of options because every functional group has
    /// caller-supplied option names — encodings, algorithms, formats — and they must all fail the same
    /// way. The public wrappers that name a specific option stay next to the options they belong to.
    /// </para>
    /// </remarks>
    internal static class OptionName
    {
        /// <summary>
        /// Resolves one option name, listing the supported names when it cannot be resolved.
        /// </summary>
        /// <typeparam name="T">The option being resolved.</typeparam>
        /// <param name="value">Caller-supplied name, or <c>null</c> to accept the default.</param>
        /// <param name="fallback">The option to use when no name was supplied.</param>
        /// <param name="description">Caller-facing name of the option, used in the failure message.</param>
        /// <returns>The resolved option.</returns>
        /// <exception cref="CryptographicRequestException">The name is not one of the supported ones.</exception>
        internal static T Parse<T>(string? value, T fallback, string description)
            where T : struct, Enum
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            var supplied = value.Trim();
            var compact = supplied
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace("_", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal);

            // Enum.TryParse also accepts the underlying numbers and comma separated combinations. Neither
            // is a name this API documents, so only plain names are considered and everything else is
            // reported with the list of names that do work.
            var looksLikeAName = compact.Length > 0
                && char.IsAsciiLetter(compact[0])
                && compact.All(char.IsAsciiLetterOrDigit);

            if (looksLikeAName && Enum.TryParse(compact, ignoreCase: true, out T parsed) && Enum.IsDefined(parsed))
            {
                return parsed;
            }

            throw new CryptographicRequestException(
                $"Unsupported {description} '{supplied}'. Supported values: {string.Join(", ", Enum.GetNames<T>())}.");
        }
    }
}
