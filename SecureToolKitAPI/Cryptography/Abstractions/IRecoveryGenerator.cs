namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates the credentials an account recovery flow needs: single-use backup codes, and a recovery
    /// key that stands on its own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are not part of a key-generation method family — there is no algorithm to select between and
    /// no key size to validate against one — so they are generated through their own abstraction rather
    /// than through <see cref="IKeyGenerator"/> and the method registry.
    /// </para>
    /// <para>
    /// Implementations must draw every value from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, must validate their options
    /// before drawing anything, and must never log, cache or store what they produce. Everything returned
    /// here is live credential material.
    /// </para>
    /// </remarks>
    public interface IRecoveryGenerator
    {
        /// <summary>
        /// Generates a set of single-use backup codes, each drawn independently of the others.
        /// </summary>
        /// <param name="spec">How many codes, how long, in which format.</param>
        /// <returns>The codes, with the strength of one code and how they must be handled.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedBackupCodes GenerateBackupCodes(BackupCodeSpec spec);

        /// <summary>
        /// Generates one recovery key, written in groups so it can be read back accurately.
        /// </summary>
        /// <param name="spec">How many groups, how long, in which format.</param>
        /// <returns>The key, its strength and how it must be handled.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedRecoveryKey GenerateRecoveryKey(RecoveryKeySpec spec);
    }
}
