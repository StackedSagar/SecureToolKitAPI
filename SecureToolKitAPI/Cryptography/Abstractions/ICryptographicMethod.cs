namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Common metadata implemented by every cryptographic method (key generation,
    /// encryption/decryption and signing) so methods can be discovered and selected by name.
    /// </summary>
    public interface ICryptographicMethod
    {
        /// <summary>Canonical method identifier used in API routes, for example <c>aes-gcm</c>.</summary>
        string Name { get; }

        /// <summary>Additional accepted identifiers for this method. Matching is case-insensitive.</summary>
        IReadOnlyCollection<string> Aliases { get; }

        /// <summary>Human readable description of the method, surfaced through the metadata endpoints.</summary>
        string Description { get; }
    }
}
