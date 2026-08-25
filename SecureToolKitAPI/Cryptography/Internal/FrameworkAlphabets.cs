namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// The character sets the framework secret endpoints draw from, written out once so the entropy a
    /// response reports and the characters it actually sampled cannot drift apart.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are not this API's own choices. Each one is the alphabet the framework's own key generator
    /// uses, reproduced so a key generated here is indistinguishable from one the framework would have
    /// produced itself. That is the whole point of these endpoints: a key the framework will accept and a
    /// team will recognise, rather than a generic random string that happens to be the right length.
    /// </para>
    /// <para>
    /// Because they are copied rather than curated, they include punctuation that
    /// <see cref="PasswordCharsets.Symbols"/> deliberately leaves out — a dollar sign, a hash, a backtick,
    /// a space. Those characters are fine where these values belong, quoted inside a settings file, and are
    /// a problem in a <c>.env</c> file or a shell, which is what the advisories on those endpoints say.
    /// Neither alphabet contains a single quote or a backslash, so the configuration snippets that quote
    /// these values cannot be broken out of.
    /// </para>
    /// <para>
    /// Nothing here selects characters. Selection is the generator's job and must go through
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>.
    /// </para>
    /// </remarks>
    internal static class FrameworkAlphabets
    {
        /// <summary>
        /// The 50 characters Django's own <c>get_random_secret_key()</c> samples a <c>SECRET_KEY</c> from:
        /// the lowercase letters, the digits and 14 punctuation marks.
        /// </summary>
        /// <remarks>
        /// Uppercase letters are absent, which is Django's choice and not an oversight — at 50 characters
        /// the key already carries far more entropy than anything using it needs.
        /// </remarks>
        internal const string DjangoSecretKey =
            PasswordCharsets.Lowercase + PasswordCharsets.Digits + "!@#$%^&*(-_=+)";

        /// <summary>
        /// The 92 characters a WordPress salt is drawn from: letters, digits and the two punctuation sets
        /// <c>wp_generate_password</c> adds when it is asked for special and extra-special characters,
        /// which is how WordPress generates the salts itself.
        /// </summary>
        /// <remarks>
        /// The extra-special set contains a space. That is intentional and matches WordPress: a salt lives
        /// inside single quotes in <c>wp-config.php</c>, where a space is unremarkable.
        /// </remarks>
        internal const string WordPressSalt =
            PasswordCharsets.Lowercase
            + PasswordCharsets.Uppercase
            + PasswordCharsets.Digits
            + "!@#$%^&*()"
            + "-_ []{}<>~`+=,.;:/?|";
    }
}
