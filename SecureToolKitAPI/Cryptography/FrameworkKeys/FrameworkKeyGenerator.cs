using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;

namespace SecureToolKitAPI.Cryptography.FrameworkKeys
{
    /// <summary>
    /// Generates the secrets a web framework asks for by name: a Django <c>SECRET_KEY</c>, a Flask
    /// <c>SECRET_KEY</c>, a Laravel <c>APP_KEY</c> and the eight WordPress authentication keys and salts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each value is produced in the shape the framework itself produces, not in a shape of this API's
    /// choosing: Django's own 50 character alphabet, the exact key length Laravel's configured cipher
    /// requires behind the <c>base64:</c> prefix it looks for, and WordPress's eight constants generated
    /// independently. A value the framework rejects, or silently accepts as the wrong length, would be worse
    /// than no value at all.
    /// </para>
    /// <para>
    /// Every value comes from <see cref="RandomNumberGenerator"/>, either as raw bytes that are then
    /// rendered as text or by sampling an alphabet, so the reported entropy is the real entropy of the
    /// process. No value is derived from another, and no value is retained after it is returned.
    /// </para>
    /// <para>
    /// The supported ranges are set so that no request can produce less than 128 bits — the strength
    /// expected of a cryptographic key — which is why there is no weak-value advisory here. The shortest
    /// key this class will generate is a 16-byte Flask or Laravel key at exactly 128 bits; the defaults are
    /// well beyond that.
    /// </para>
    /// <para>
    /// The class is stateless and therefore safe to share as a singleton. Raw byte buffers are cleared once
    /// the text form has been built; the returned strings are immutable and can only be discarded by the
    /// caller.
    /// </para>
    /// </remarks>
    public sealed class FrameworkKeyGenerator : IFrameworkKeyGenerator
    {
        /// <summary>
        /// The eight constants WordPress looks up by name, in the order its own configuration file lists
        /// them. Not secret, and not open to change: WordPress reads these exact names.
        /// </summary>
        private static readonly string[] WordPressSaltNames =
        [
            "AUTH_KEY",
            "SECURE_AUTH_KEY",
            "LOGGED_IN_KEY",
            "NONCE_KEY",
            "AUTH_SALT",
            "SECURE_AUTH_SALT",
            "LOGGED_IN_SALT",
            "NONCE_SALT"
        ];

        /// <summary>The prefix Laravel requires in front of a Base64 encoded application key.</summary>
        private const string LaravelKeyPrefix = "base64:";

        /// <inheritdoc />
        public GeneratedFrameworkKey GenerateDjangoSecretKey(DjangoSecretKeySpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var alphabet = FrameworkAlphabets.DjangoSecretKey;
            var value = SecretText.Sample(alphabet, spec.Length);

            return Describe(
                "Django",
                "SECRET_KEY",
                value,
                PasswordStrength.EntropyBits(spec.Length, alphabet.Length),
                spec.Describe(),
                warnings:
                [
                    "SECRET_KEY signs sessions, password reset tokens, CSRF tokens, signed cookies and "
                    + "anything else that goes through Django's signing helpers. Replacing it logs every user "
                    + "out and invalidates every password reset link that has not been used yet.",
                    "Read it from the environment or a secrets manager. A key written into settings.py and "
                    + "committed is a key that has to be replaced, and every environment needs its own: a "
                    + "development key that reaches production signs production sessions.",
                    "Django's alphabet includes $, # and % because Django's own generator does. Some .env "
                    + "parsers and every shell give those characters a meaning, so quote the value where you "
                    + "store it rather than pasting it bare."
                ]);
        }

        /// <inheritdoc />
        public GeneratedFrameworkKey GenerateFlaskSecretKey(FlaskSecretKeySpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var (value, entropyBits) = SecretText.Material(spec.Bytes, spec.Encoding);

            return Describe(
                "Flask",
                "SECRET_KEY",
                value,
                entropyBits,
                $"{spec.Describe()} ({value.Length} characters)",
                warnings:
                [
                    "Flask signs its session cookie with this key. It does not encrypt it — whatever you put "
                    + "in the session is readable by the client, and this key only stops the client changing "
                    + "it. Never put anything confidential in a Flask session.",
                    "Extensions that sign their own values, such as Flask-WTF's CSRF tokens and anything "
                    + "built on itsdangerous, use this same key by default. Replacing it invalidates those "
                    + "along with every existing session cookie.",
                    "Read it from the environment rather than writing it into the application, and give each "
                    + "environment its own. Flask falls back to an insecure default only in the sense that it "
                    + "refuses to sign at all — an application running without this set is not protected."
                ]);
        }

        /// <inheritdoc />
        public GeneratedFrameworkKey GenerateLaravelAppKey(LaravelAppKeySpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            // Laravel reads the key by stripping the prefix and Base64 decoding the rest, so the prefix is
            // required, is not secret, and adds nothing to the entropy.
            var (encoded, entropyBits) = SecretText.Material(spec.KeyBytes, SecretEncoding.Base64);

            return Describe(
                "Laravel",
                "APP_KEY",
                LaravelKeyPrefix + encoded,
                entropyBits,
                spec.Describe(),
                spec.CipherName,
                [
                    $"Laravel expects exactly this shape for {spec.CipherName}: the base64: prefix followed "
                    + $"by {spec.KeyBytes} Base64 encoded bytes. Changing config('app.cipher') without "
                    + "generating a matching key stops the application booting.",
                    "This key encrypts cookies, sessions, signed URLs and everything passed through Crypt or "
                    + "an encrypted model cast. Replacing it makes all of that undecryptable, including "
                    + "remembered logins and any encrypted database column.",
                    "Put it in .env and nowhere else. Never commit .env, and never hard-code the key in "
                    + "config/app.php where it would end up in version control and in cached configuration."
                ]);
        }

        /// <inheritdoc />
        public GeneratedFrameworkSalts GenerateWordPressSalts(WordPressSaltSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            spec.Validate();

            var alphabet = FrameworkAlphabets.WordPressSalt;

            // Each value is sampled on its own, so one of them leaking says nothing about the other seven.
            // That independence is the reason WordPress asks for eight rather than one.
            var salts = new FrameworkSalt[WordPressSaltNames.Length];

            for (var index = 0; index < WordPressSaltNames.Length; index++)
            {
                salts[index] = new FrameworkSalt
                {
                    Name = WordPressSaltNames[index],
                    Value = SecretText.Sample(alphabet, spec.Length)
                };
            }

            var entropyBits = PasswordStrength.Round(
                PasswordStrength.EntropyBits(spec.Length, alphabet.Length));

            return new GeneratedFrameworkSalts
            {
                Framework = "WordPress",
                Salts = salts,
                Count = salts.Length,
                Length = spec.Length,
                EntropyBits = entropyBits,
                Strength = PasswordStrength.Describe(entropyBits),
                Composition = spec.Describe(),
                Configuration = Configuration(salts),
                Warnings =
                [
                    "These eight values are what makes a stolen WordPress authentication cookie useless "
                    + "anywhere else. Replacing them logs every user out immediately, which is exactly what "
                    + "you want after a compromise and an inconvenience the rest of the time.",
                    "Paste the block into wp-config.php in place of the existing define lines. Keep all "
                    + "eight names exactly as they are — WordPress looks these constants up by name, and a "
                    + "missing one silently falls back to a weaker default.",
                    "Every value here was generated independently. Never reuse one across two constants, and "
                    + "never copy a block from a tutorial, a forum post or a paste bin: a published salt is "
                    + "not a salt.",
                    "The values contain spaces and punctuation, which is why the block puts each one in "
                    + "single quotes. They contain no single quote and no backslash, so nothing in them can "
                    + "break out of those quotes."
                ]
            };
        }

        /// <summary>
        /// Builds the <c>wp-config.php</c> block, with every value single-quoted.
        /// </summary>
        /// <param name="salts">The generated values.</param>
        /// <returns>
        /// The block, one <c>define</c> per line separated by line feeds. Secret, because it contains every
        /// value.
        /// </returns>
        /// <remarks>
        /// Single quotes are safe here without escaping because the alphabet contains neither a single quote
        /// nor a backslash, which is asserted by the tests rather than assumed. Line feeds are used rather
        /// than the platform separator so the block is the same wherever this API runs.
        /// </remarks>
        private static string Configuration(IReadOnlyList<FrameworkSalt> salts) =>
            string.Join("\n", salts.Select(salt => $"define( '{salt.Name}', '{salt.Value}' );"));

        /// <summary>
        /// Wraps a generated value with the figures that describe it.
        /// </summary>
        /// <param name="framework">The framework the value was generated for.</param>
        /// <param name="setting">The configuration name the value belongs under.</param>
        /// <param name="value">The generated value, including any required prefix.</param>
        /// <param name="entropyBits">Entropy of the generation process, before rounding.</param>
        /// <param name="composition">Description of how the value was built.</param>
        /// <param name="kind">The specific shape asked for, when the framework has one.</param>
        /// <param name="warnings">Advisories specific to this framework.</param>
        /// <remarks>
        /// The strength label is derived from the rounded figure that is reported, so a response can never
        /// show a number and a label that disagree.
        /// </remarks>
        private static GeneratedFrameworkKey Describe(
            string framework,
            string setting,
            string value,
            double entropyBits,
            string composition,
            string? kind = null,
            IReadOnlyList<string>? warnings = null)
        {
            var rounded = PasswordStrength.Round(entropyBits);

            return new GeneratedFrameworkKey
            {
                Framework = framework,
                Setting = setting,
                Value = value,
                Length = value.Length,
                EntropyBits = rounded,
                Strength = PasswordStrength.Describe(rounded),
                Composition = composition,
                Kind = kind,
                Warnings = warnings ?? []
            };
        }
    }
}
