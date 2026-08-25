using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.Salts
{
    /// <summary>
    /// Generates salts from the platform's cryptographically secure random number generator.
    /// </summary>
    /// <remarks>
    /// Holds no state and draws every value independently, so one instance is shared by every request.
    /// The advisories are constant because they describe how a salt must be used, which does not depend on
    /// the options the caller chose.
    /// </remarks>
    public sealed class SaltGenerator : ISaltGenerator
    {
        /// <inheritdoc />
        public GeneratedSalt Generate(SaltSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            return new GeneratedSalt
            {
                Value = SecretText.Encode(spec.Bytes, spec.Encoding),
                Bytes = spec.Bytes,
                Format = $"{SecretText.Describe(spec.Encoding)}, {spec.Bytes} random bytes.",
                Warnings =
                [
                    "A salt is not a secret and does not need to be hidden, but it must be stored with the "
                    + "hash it was used for. Without it the hash cannot be verified.",
                    "Generate a new salt for every value hashed. Reusing one lets identical inputs produce "
                    + "identical hashes, which is the thing a salt exists to prevent.",
                    "A salt is not a substitute for a password-hashing function. Use it with a deliberately "
                    + "slow algorithm such as PBKDF2, scrypt or Argon2, not with a bare SHA-256."
                ]
            };
        }
    }
}
