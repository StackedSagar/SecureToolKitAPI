using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.FrameworkKeys;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The framework key generator: that each value comes out in the shape the framework itself would have
    /// produced, that the reported entropy matches what was actually drawn, that WordPress's eight values are
    /// independent of one another and of the block that quotes them, and that unusable options are refused
    /// before any randomness is drawn.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything this generator produces is live secret material, so no assertion prints a generated value.
    /// Membership, uniqueness and containment are checked through booleans with a message that describes the
    /// defect instead of showing the value.
    /// </para>
    /// <para>
    /// The expected alphabets are written out here rather than read from the implementation, so a change to
    /// the constants the generator samples from fails these tests instead of travelling through them. They
    /// are the framework's own alphabets: if one of these literals has to change, a framework changed its
    /// generator, and that is worth noticing.
    /// </para>
    /// </remarks>
    public class FrameworkKeyGeneratorTests
    {
        /// <summary>The 50 characters Django's <c>get_random_secret_key()</c> samples from.</summary>
        private const string DjangoAlphabet =
            "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)";

        /// <summary>The 92 characters WordPress generates its salts from, including the space.</summary>
        private const string WordPressAlphabet =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            + "!@#$%^&*()"
            + "-_ []{}<>~`+=,.;:/?|";

        /// <summary>The prefix Laravel requires in front of a Base64 encoded application key.</summary>
        private const string LaravelPrefix = "base64:";

        /// <summary>
        /// How many values the uniqueness checks draw. Enough that a generator reusing one would fail
        /// reliably, small enough to keep the suite fast.
        /// </summary>
        private const int Iterations = 50;

        /// <summary>
        /// The strength every framework secret has to reach. The supported ranges are set so that no
        /// request can produce less, which is asserted rather than assumed.
        /// </summary>
        private const double CryptographicKeyBits = 128d;

        private readonly FrameworkKeyGenerator _generator = new();

        [Fact]
        public void The_default_django_key_is_the_fifty_characters_django_itself_produces()
        {
            var result = _generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec());

            Assert.Equal("Django", result.Framework);
            Assert.Equal("SECRET_KEY", result.Setting);
            Assert.Equal(50, result.Length);

            // Fifty characters over Django's fifty symbols, about 5.64 bits each.
            Assert.Equal(282.2d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal(
                "50 characters sampled from Django's own alphabet of lowercase letters, digits and "
                + "punctuation (50 symbols)",
                result.Composition);

            // Django's key has no cipher or variant to report.
            Assert.Null(result.Kind);
        }

        [Fact]
        public void A_django_key_contains_only_djangos_own_alphabet()
        {
            var result = _generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec { Length = 128 });

            Assert.True(
                result.Value.All(character => DjangoAlphabet.Contains(character, StringComparison.Ordinal)),
                "The Django key contained a character outside the alphabet Django samples from.");

            // Django's alphabet is deliberately lowercase, so an uppercase letter would mean the wrong set.
            Assert.False(
                result.Value.Any(char.IsUpper),
                "The Django key contained an uppercase letter, which Django's own alphabet does not include.");
        }

        [Theory]
        [InlineData(32, 180.6d)]
        [InlineData(50, 282.2d)]
        [InlineData(64, 361.2d)]
        [InlineData(128, 722.4d)]
        public void A_django_key_carries_the_entropy_its_length_implies(int length, double expectedBits)
        {
            var result = _generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec { Length = length });

            Assert.Equal(length, result.Value.Length);
            Assert.Equal(length, result.Length);
            Assert.Equal(expectedBits, result.EntropyBits);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(31)]
        [InlineData(129)]
        [InlineData(int.MaxValue)]
        public void A_django_key_length_outside_the_supported_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec { Length = length }));

            Assert.Contains("between 32 and 128 characters", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_django_advisories_say_what_rotation_costs_and_where_the_key_belongs()
        {
            var result = _generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec());

            Assert.Equal(3, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("logs every user out", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("settings.py", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("quote the value", StringComparison.Ordinal));
        }

        [Fact]
        public void The_default_flask_key_is_what_secrets_token_hex_would_have_produced()
        {
            var result = _generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec());

            Assert.Equal("Flask", result.Framework);
            Assert.Equal("SECRET_KEY", result.Setting);

            // Thirty-two bytes as hexadecimal: two characters per byte, eight bits per byte.
            Assert.Equal(64, result.Length);
            Assert.Equal(256d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal("256 random bits, hexadecimal (64 characters)", result.Composition);
            Assert.Null(result.Kind);

            Assert.True(
                result.Value.All(Uri.IsHexDigit),
                "The default Flask key contained something that is not a hexadecimal digit.");
        }

        [Theory]
        [InlineData(SecretEncoding.Hex, 64, 256d, "256 random bits, hexadecimal (64 characters)")]
        [InlineData(SecretEncoding.HexUpper, 64, 256d, "256 random bits, uppercase hexadecimal (64 characters)")]
        [InlineData(SecretEncoding.Base64, 44, 256d, "256 random bits, Base64 encoded (44 characters)")]
        [InlineData(SecretEncoding.Base64Url, 43, 256d, "256 random bits, Base64url encoded (43 characters)")]
        [InlineData(
            SecretEncoding.Base62,
            43,
            256d,
            "256 random bits, sampled from 62 digits and letters (43 characters)")]
        public void A_flask_key_is_rendered_in_the_requested_encoding(
            SecretEncoding encoding,
            int expectedLength,
            double expectedBits,
            string expectedComposition)
        {
            var result = _generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec { Encoding = encoding });

            Assert.Equal(expectedLength, result.Value.Length);
            Assert.Equal(expectedLength, result.Length);
            Assert.Equal(expectedBits, result.EntropyBits);
            Assert.Equal(expectedComposition, result.Composition);
        }

        [Theory]
        [InlineData(16, 128d)]
        [InlineData(32, 256d)]
        [InlineData(64, 512d)]
        [InlineData(128, 1024d)]
        public void A_flask_key_carries_the_entropy_its_size_implies(int bytes, double expectedBits)
        {
            var result = _generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec { Bytes = bytes });

            Assert.Equal(bytes * 2, result.Length);
            Assert.Equal(expectedBits, result.EntropyBits);
        }

        [Fact]
        public void A_base62_flask_key_is_never_weaker_than_the_size_that_was_asked_for()
        {
            // Base62 is sampled rather than re-based, so it takes whole characters: 22 of them to carry 128
            // bits, which comes to slightly more. Rounding up is the only safe direction.
            var result = _generator.GenerateFlaskSecretKey(
                new FlaskSecretKeySpec { Bytes = 16, Encoding = SecretEncoding.Base62 });

            Assert.Equal(22, result.Length);
            Assert.Equal(131d, result.EntropyBits);
            Assert.True(
                result.EntropyBits >= 16 * 8d,
                "A Base62 key carried less entropy than the number of bytes that were asked for.");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(15)]
        [InlineData(129)]
        [InlineData(int.MaxValue)]
        public void A_flask_key_size_outside_the_supported_range_is_refused(int bytes)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec { Bytes = bytes }));

            Assert.Contains("between 16 and 128 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_flask_encoding_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateFlaskSecretKey(
                    new FlaskSecretKeySpec { Encoding = (SecretEncoding)873 }));

            Assert.Contains("not supported", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_flask_advisories_say_the_session_is_signed_rather_than_encrypted()
        {
            var result = _generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec());

            Assert.Equal(3, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("It does not encrypt it", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("itsdangerous", StringComparison.Ordinal));
        }

        [Fact]
        public void The_default_laravel_key_is_sized_for_laravels_default_cipher()
        {
            var result = _generator.GenerateLaravelAppKey(new LaravelAppKeySpec());

            Assert.Equal("Laravel", result.Framework);
            Assert.Equal("APP_KEY", result.Setting);
            Assert.Equal("aes-256-cbc", result.Kind);

            // The prefix is seven characters and the Base64 of thirty-two bytes is forty-four.
            Assert.Equal(51, result.Length);
            Assert.Equal(256d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal(
                "256 random bits for aes-256-cbc, Base64 encoded behind Laravel's base64: prefix",
                result.Composition);
        }

        [Theory]
        [InlineData(LaravelCipher.Aes256Cbc, "aes-256-cbc", 32, 51, 256d)]
        [InlineData(LaravelCipher.Aes128Cbc, "aes-128-cbc", 16, 31, 128d)]
        [InlineData(LaravelCipher.Aes256Gcm, "aes-256-gcm", 32, 51, 256d)]
        [InlineData(LaravelCipher.Aes128Gcm, "aes-128-gcm", 16, 31, 128d)]
        public void A_laravel_key_decodes_to_exactly_the_length_its_cipher_requires(
            LaravelCipher cipher,
            string expectedName,
            int expectedBytes,
            int expectedLength,
            double expectedBits)
        {
            var result = _generator.GenerateLaravelAppKey(new LaravelAppKeySpec { Cipher = cipher });

            Assert.Equal(expectedName, result.Kind);
            Assert.Equal(expectedLength, result.Length);
            Assert.Equal(expectedBits, result.EntropyBits);

            Assert.True(
                result.Value.StartsWith(LaravelPrefix, StringComparison.Ordinal),
                "The Laravel key did not start with the base64: prefix Laravel looks for.");

            // Laravel reads the key by stripping the prefix and Base64 decoding the rest, so this is exactly
            // the check that decides whether the application boots.
            var decoded = Convert.FromBase64String(result.Value[LaravelPrefix.Length..]);

            Assert.Equal(expectedBytes, decoded.Length);
        }

        [Fact]
        public void The_laravel_prefix_is_not_counted_towards_the_entropy()
        {
            var result = _generator.GenerateLaravelAppKey(new LaravelAppKeySpec());

            // Fifty-one characters of value, but only the thirty-two decoded bytes are random.
            Assert.Equal(51, result.Length);
            Assert.Equal(256d, result.EntropyBits);
        }

        [Fact]
        public void A_laravel_cipher_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateLaravelAppKey(
                    new LaravelAppKeySpec { Cipher = (LaravelCipher)451 }));

            Assert.Contains("not supported", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_laravel_advisories_name_the_cipher_and_what_rotation_makes_unreadable()
        {
            var result = _generator.GenerateLaravelAppKey(
                new LaravelAppKeySpec { Cipher = LaravelCipher.Aes128Gcm });

            Assert.Equal(3, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("aes-128-gcm", StringComparison.Ordinal)
                    && warning.Contains("16 Base64 encoded bytes", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("undecryptable", StringComparison.Ordinal));
        }

        [Fact]
        public void The_default_wordpress_salts_are_the_eight_constants_wordpress_reads()
        {
            var result = _generator.GenerateWordPressSalts(new WordPressSaltSpec());

            Assert.Equal("WordPress", result.Framework);
            Assert.Equal(8, result.Count);
            Assert.Equal(8, result.Salts.Count);
            Assert.Equal(64, result.Length);

            // Sixty-four characters over ninety-two symbols, about 6.52 bits each.
            Assert.Equal(417.5d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal(
                "64 characters sampled from WordPress's own alphabet of letters, digits and punctuation "
                + "(92 symbols)",
                result.Composition);

            Assert.Equal(
                new[]
                {
                    "AUTH_KEY",
                    "SECURE_AUTH_KEY",
                    "LOGGED_IN_KEY",
                    "NONCE_KEY",
                    "AUTH_SALT",
                    "SECURE_AUTH_SALT",
                    "LOGGED_IN_SALT",
                    "NONCE_SALT"
                },
                result.Salts.Select(salt => salt.Name).ToArray());
        }

        [Fact]
        public void Every_wordpress_salt_is_the_requested_length_and_from_wordpresss_own_alphabet()
        {
            var result = _generator.GenerateWordPressSalts(new WordPressSaltSpec { Length = 32 });

            Assert.All(result.Salts, salt => Assert.Equal(32, salt.Value.Length));
            Assert.All(
                result.Salts,
                salt => Assert.True(
                    salt.Value.All(character =>
                        WordPressAlphabet.Contains(character, StringComparison.Ordinal)),
                    "A WordPress salt contained a character outside the alphabet WordPress samples from."));
        }

        [Fact]
        public void The_eight_wordpress_salts_are_drawn_independently_of_each_other()
        {
            var result = _generator.GenerateWordPressSalts(new WordPressSaltSpec());

            var distinct = new HashSet<string>(
                result.Salts.Select(salt => salt.Value),
                StringComparer.Ordinal);

            Assert.Equal(result.Salts.Count, distinct.Count);
        }

        [Fact]
        public void Two_sets_of_wordpress_salts_never_overlap()
        {
            var first = _generator.GenerateWordPressSalts(new WordPressSaltSpec());
            var second = _generator.GenerateWordPressSalts(new WordPressSaltSpec());

            Assert.False(
                first.Salts
                    .Select(salt => salt.Value)
                    .Intersect(second.Salts.Select(salt => salt.Value), StringComparer.Ordinal)
                    .Any(),
                "Two sets of WordPress salts shared a value, so the randomness is not working.");
        }

        [Fact]
        public void The_configuration_block_defines_each_constant_once_with_its_own_value()
        {
            var result = _generator.GenerateWordPressSalts(new WordPressSaltSpec());

            var lines = result.Configuration.Split('\n');

            Assert.Equal(result.Salts.Count, lines.Length);

            for (var index = 0; index < lines.Length; index++)
            {
                var salt = result.Salts[index];

                Assert.True(
                    string.Equals(
                        lines[index],
                        $"define( '{salt.Name}', '{salt.Value}' );",
                        StringComparison.Ordinal),
                    $"The configuration line for {salt.Name} did not define that constant with its value.");
            }
        }

        [Fact]
        public void The_configuration_block_can_be_single_quoted_without_escaping()
        {
            var result = _generator.GenerateWordPressSalts(new WordPressSaltSpec { Length = 128 });

            // The block quotes every value with single quotes and escapes nothing, which is only safe while
            // the alphabet contains neither a single quote nor a backslash.
            Assert.All(
                result.Salts,
                salt => Assert.False(
                    salt.Value.Contains('\'', StringComparison.Ordinal)
                    || salt.Value.Contains('\\', StringComparison.Ordinal),
                    "A WordPress salt contained a quote or a backslash, which would break out of the block."));

            // Four apostrophes per line and no more: two around the constant name, two around the value.
            // Anything above that count is a value carrying a quote of its own.
            Assert.Equal(
                result.Salts.Count * 4,
                result.Configuration.Count(character => character == '\''));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(31)]
        [InlineData(129)]
        [InlineData(int.MaxValue)]
        public void A_wordpress_salt_length_outside_the_supported_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateWordPressSalts(new WordPressSaltSpec { Length = length }));

            Assert.Contains("between 32 and 128 characters", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_wordpress_advisories_say_what_replacing_them_does_and_not_to_copy_a_published_set()
        {
            var result = _generator.GenerateWordPressSalts(new WordPressSaltSpec());

            Assert.Equal(4, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("logs every user out", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("wp-config.php", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("a published salt is not a salt", StringComparison.Ordinal));
        }

        [Fact]
        public void Every_framework_key_is_drawn_independently_of_the_last()
        {
            var django = new HashSet<string>(StringComparer.Ordinal);
            var flask = new HashSet<string>(StringComparer.Ordinal);
            var laravel = new HashSet<string>(StringComparer.Ordinal);

            for (var iteration = 0; iteration < Iterations; iteration++)
            {
                django.Add(_generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec()).Value);
                flask.Add(_generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec()).Value);
                laravel.Add(_generator.GenerateLaravelAppKey(new LaravelAppKeySpec()).Value);
            }

            Assert.Equal(Iterations, django.Count);
            Assert.Equal(Iterations, flask.Count);
            Assert.Equal(Iterations, laravel.Count);
        }

        [Fact]
        public void Even_the_smallest_supported_options_reach_cryptographic_key_strength()
        {
            var django = _generator.GenerateDjangoSecretKey(
                new DjangoSecretKeySpec { Length = DjangoSecretKeySpec.MinimumLength });

            var flask = _generator.GenerateFlaskSecretKey(
                new FlaskSecretKeySpec { Bytes = FlaskSecretKeySpec.MinimumBytes });

            var laravel = _generator.GenerateLaravelAppKey(
                new LaravelAppKeySpec { Cipher = LaravelCipher.Aes128Cbc });

            var wordpress = _generator.GenerateWordPressSalts(
                new WordPressSaltSpec { Length = WordPressSaltSpec.MinimumLength });

            // Nothing these endpoints can be asked for is weaker than a cryptographic key, which is why no
            // response here carries a low-entropy advisory.
            Assert.True(
                django.EntropyBits >= CryptographicKeyBits,
                "The shortest supported Django key was below cryptographic key strength.");
            Assert.True(
                flask.EntropyBits >= CryptographicKeyBits,
                "The smallest supported Flask key was below cryptographic key strength.");
            Assert.True(
                laravel.EntropyBits >= CryptographicKeyBits,
                "The smallest supported Laravel key was below cryptographic key strength.");
            Assert.True(
                wordpress.EntropyBits >= CryptographicKeyBits,
                "The shortest supported WordPress salt was below cryptographic key strength.");
        }

        [Fact]
        public void The_boundaries_of_the_supported_ranges_are_accepted()
        {
            Assert.Equal(
                DjangoSecretKeySpec.MinimumLength,
                _generator.GenerateDjangoSecretKey(
                    new DjangoSecretKeySpec { Length = DjangoSecretKeySpec.MinimumLength }).Length);

            Assert.Equal(
                DjangoSecretKeySpec.MaximumLength,
                _generator.GenerateDjangoSecretKey(
                    new DjangoSecretKeySpec { Length = DjangoSecretKeySpec.MaximumLength }).Length);

            Assert.Equal(
                FlaskSecretKeySpec.MinimumBytes * 2,
                _generator.GenerateFlaskSecretKey(
                    new FlaskSecretKeySpec { Bytes = FlaskSecretKeySpec.MinimumBytes }).Length);

            Assert.Equal(
                FlaskSecretKeySpec.MaximumBytes * 2,
                _generator.GenerateFlaskSecretKey(
                    new FlaskSecretKeySpec { Bytes = FlaskSecretKeySpec.MaximumBytes }).Length);

            Assert.Equal(
                WordPressSaltSpec.MinimumLength,
                _generator.GenerateWordPressSalts(
                    new WordPressSaltSpec { Length = WordPressSaltSpec.MinimumLength }).Length);

            Assert.Equal(
                WordPressSaltSpec.MaximumLength,
                _generator.GenerateWordPressSalts(
                    new WordPressSaltSpec { Length = WordPressSaltSpec.MaximumLength }).Length);
        }

        [Fact]
        public void Generating_without_options_is_rejected_rather_than_silently_defaulted()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateDjangoSecretKey(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateFlaskSecretKey(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateLaravelAppKey(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateWordPressSalts(null!));
        }

        [Fact]
        public void No_framework_response_repeats_a_value_in_a_field_that_is_meant_to_be_safe_to_log()
        {
            var django = _generator.GenerateDjangoSecretKey(new DjangoSecretKeySpec());
            var flask = _generator.GenerateFlaskSecretKey(new FlaskSecretKeySpec());
            var laravel = _generator.GenerateLaravelAppKey(new LaravelAppKeySpec());
            var wordpress = _generator.GenerateWordPressSalts(new WordPressSaltSpec());

            AssertDescribesWithoutRevealing(django.Composition, django.Warnings, django.Value);
            AssertDescribesWithoutRevealing(flask.Composition, flask.Warnings, flask.Value);
            AssertDescribesWithoutRevealing(
                laravel.Composition,
                laravel.Warnings,
                laravel.Value[LaravelPrefix.Length..]);

            foreach (var salt in wordpress.Salts)
            {
                AssertDescribesWithoutRevealing(wordpress.Composition, wordpress.Warnings, salt.Value);
            }
        }

        /// <summary>
        /// Asserts that the fields meant to be safe to show and to log contain no part of the secret.
        /// </summary>
        /// <param name="composition">The composition the generator reported.</param>
        /// <param name="warnings">The advisories the generator attached.</param>
        /// <param name="secret">The generated value, or the random part of it.</param>
        /// <remarks>
        /// The message names the field rather than showing what leaked, so a failure here does not print the
        /// secret it just caught being printed.
        /// </remarks>
        private static void AssertDescribesWithoutRevealing(
            string composition,
            IReadOnlyList<string> warnings,
            string secret)
        {
            Assert.False(
                composition.Contains(secret, StringComparison.Ordinal),
                "The composition contained the generated value, which is meant to be safe to log.");

            Assert.All(
                warnings,
                warning => Assert.False(
                    warning.Contains(secret, StringComparison.Ordinal),
                    "An advisory contained the generated value, which is meant to be safe to log."));
        }
    }
}
