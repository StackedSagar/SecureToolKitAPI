namespace SecureToolKitAPI.Cryptography.Abstractions
{
    /// <summary>
    /// Generates the identity and second-factor values an account needs: UUIDs, TOTP shared secrets, the
    /// enrollment URI an authenticator scans, the code a secret currently produces, and Base32 rendering.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are not a family of interchangeable algorithms — there is no method to select between and no
    /// key size to validate against one — so they are generated through their own abstraction rather than
    /// through <see cref="IKeyGenerator"/> and the method registry.
    /// </para>
    /// <para>
    /// Implementations must draw every value from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, must validate their options before
    /// drawing anything, and must never log, cache or store what they produce or what they are given. A
    /// TOTP secret is a complete second factor, and the enrollment URI contains it.
    /// </para>
    /// <para>
    /// <see cref="ComputeTotpCode"/> is the one operation here that takes secret material in rather than
    /// handing it out. It exists so an enrollment can be checked end to end; it verifies nothing and
    /// authenticates nobody, because the caller already holds the secret.
    /// </para>
    /// </remarks>
    public interface IIdentityGenerator
    {
        /// <summary>Generates a batch of UUIDs.</summary>
        /// <param name="spec">How many, which version, in which format.</param>
        /// <returns>The identifiers, with the random bits one of them carries.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedUuids GenerateUuids(UuidSpec spec);

        /// <summary>Generates a TOTP shared secret sized for the chosen hash function.</summary>
        /// <param name="spec">Size and the parameters the secret will be used with.</param>
        /// <returns>The secret, Base32 encoded, with the parameters it must be enrolled with.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are outside the supported ranges.</exception>
        GeneratedTotpSecret GenerateTotpSecret(TotpSecretSpec spec);

        /// <summary>
        /// Builds a complete TOTP enrollment: a secret, or the one supplied, together with the
        /// <c>otpauth</c> URI an authenticator application reads from a QR code.
        /// </summary>
        /// <param name="spec">Issuer, account, an optional existing secret, and the parameters.</param>
        /// <returns>The enrollment, whose URI contains the secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The options are missing or unusable.</exception>
        TotpEnrollment CreateTotpEnrollment(TotpEnrollmentSpec spec);

        /// <summary>
        /// Computes the code a secret produces at a given moment, so an enrollment can be checked against
        /// what the person's authenticator is showing.
        /// </summary>
        /// <param name="spec">The Base32 secret, its parameters, and the moment to compute for.</param>
        /// <returns>The code, the counter it came from and how long it lasts.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The secret or the parameters are unusable.</exception>
        TotpCode ComputeTotpCode(TotpCodeSpec spec);

        /// <summary>Renders bytes as Base32.</summary>
        /// <param name="spec">The input, as text or Base64, and how to write the result.</param>
        /// <returns>The encoded value, with the reminder that encoding is not encryption.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="spec"/> is <c>null</c>.</exception>
        /// <exception cref="CryptographicRequestException">The input is missing, malformed or too large.</exception>
        EncodedText EncodeBase32(Base32Spec spec);
    }
}
