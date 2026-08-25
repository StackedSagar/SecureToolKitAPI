using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.DeveloperSecrets;
using SecureToolKitAPI.Cryptography.Internal;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The developer secret generator: that it produces the shape and size each kind of credential calls
    /// for, refuses options it cannot satisfy, and reports figures that match what it actually did.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These tests generate secrets, so no assertion is allowed to print one. Anything that inspects a
    /// generated value asserts through <see cref="Assert.True(bool, string)"/> with a message that names
    /// the problem instead of showing the value, and nothing here uses a fixed or production secret.
    /// </para>
    /// <para>
    /// Randomness cannot be seeded — the generator draws from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, which is the point — so it is
    /// checked by repeating a generation and asserting a property that must hold every time.
    /// </para>
    /// </remarks>
    public class DeveloperSecretGeneratorTests
    {
        /// <summary>
        /// How many times a property is re-checked. Enough that a generator ignoring an alphabet would
        /// fail reliably, small enough to keep the suite fast.
        /// </summary>
        private const int Iterations = 50;

        private readonly DeveloperSecretGenerator _generator = new();

        [Fact]
        public void The_default_api_key_is_256_bits_rendered_as_base64url()
        {
            var result = _generator.GenerateApiKey(new ByteSecretSpec());

            // 32 bytes is 44 Base64 characters including one padding character, which Base64url drops.
            Assert.Equal(43, result.Length);
            Assert.Equal(43, result.Value.Length);
            Assert.Equal(256d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal("256 random bits, Base64url encoded (43 characters)", result.Composition);
            Assert.Null(result.Kind);
            Assert.Empty(result.Warnings);
        }

        [Theory]
        [InlineData(SecretEncoding.Base64Url, 32, 43)]
        [InlineData(SecretEncoding.Base64, 32, 44)]
        [InlineData(SecretEncoding.Hex, 32, 64)]
        [InlineData(SecretEncoding.HexUpper, 32, 64)]
        [InlineData(SecretEncoding.Base62, 32, 43)]
        [InlineData(SecretEncoding.Base64Url, 16, 22)]
        [InlineData(SecretEncoding.Hex, 16, 32)]
        [InlineData(SecretEncoding.Base64, 48, 64)]
        [InlineData(SecretEncoding.Base64Url, 64, 86)]
        [InlineData(SecretEncoding.Base62, 128, 172)]
        public void An_api_key_has_the_length_its_encoding_implies(
            SecretEncoding encoding,
            int bytes,
            int expectedLength)
        {
            var result = _generator.GenerateApiKey(new ByteSecretSpec { Bytes = bytes, Encoding = encoding });

            Assert.Equal(expectedLength, result.Value.Length);
            Assert.Equal(result.Value.Length, result.Length);

            // No encoding may deliver less than the strength that was asked for. Base62 is sampled rather
            // than re-based, so it lands slightly above the request instead of exactly on it.
            Assert.True(
                result.EntropyBits >= bytes * 8d,
                "The reported entropy was lower than the number of random bits requested.");
        }

        [Theory]
        [InlineData(SecretEncoding.Base64Url, SecretText.Base64UrlAlphabet)]
        [InlineData(SecretEncoding.Hex, SecretText.HexLower)]
        [InlineData(SecretEncoding.HexUpper, SecretText.HexUpper)]
        [InlineData(SecretEncoding.Base62, SecretText.Base62)]
        public void An_encoding_uses_only_the_characters_it_promises(SecretEncoding encoding, string alphabet)
        {
            for (var attempt = 0; attempt < Iterations; attempt++)
            {
                var value = _generator.GenerateApiKey(new ByteSecretSpec { Encoding = encoding }).Value;

                Assert.True(
                    value.All(character => alphabet.Contains(character, StringComparison.Ordinal)),
                    "A generated value contained a character from outside its own encoding alphabet.");
            }
        }

        [Fact]
        public void A_prefix_is_placed_in_front_of_the_random_part_and_reported_only_by_length()
        {
            const string prefix = "sk_live_";

            var result = _generator.GenerateApiKey(new ByteSecretSpec { Prefix = prefix });

            Assert.True(
                result.Value.StartsWith(prefix, StringComparison.Ordinal),
                "The generated key did not begin with the requested prefix.");

            Assert.Equal(prefix.Length + 43, result.Length);

            // A prefix adds no randomness, so it must not change the reported entropy.
            Assert.Equal(256d, result.EntropyBits);

            Assert.Contains($"behind a {prefix.Length} character prefix", result.Composition, StringComparison.Ordinal);
            Assert.DoesNotContain(prefix, result.Composition, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(ByteSecretSpec.MinimumBytes - 1)]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(ByteSecretSpec.MaximumBytes + 1)]
        public void An_api_key_size_outside_the_supported_range_is_refused(int bytes)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateApiKey(new ByteSecretSpec { Bytes = bytes }));

            Assert.Contains("between 16 and 128 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("sk live ")]
        [InlineData("sk/live/")]
        [InlineData("sk:live:")]
        [InlineData("sk+live+")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaa")]
        public void A_prefix_that_would_not_survive_a_url_or_a_log_line_is_refused(string prefix)
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateApiKey(new ByteSecretSpec { Prefix = prefix }));
        }

        [Fact]
        public void An_undefined_encoding_is_refused_rather_than_falling_through_to_a_default()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateApiKey(new ByteSecretSpec { Encoding = (SecretEncoding)99 }));

            Assert.Contains("encoding is not supported", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(JwtAlgorithm.HS256, 256, 44)]
        [InlineData(JwtAlgorithm.HS384, 384, 64)]
        [InlineData(JwtAlgorithm.HS512, 512, 88)]
        public void A_jwt_secret_is_sized_for_its_algorithm(JwtAlgorithm algorithm, int bits, int length)
        {
            var result = _generator.GenerateJwtSecret(new JwtSecretSpec { Algorithm = algorithm });

            // RFC 7518 requires a key at least as long as the hash output, so the algorithm settles the
            // size and the caller cannot weaken it.
            Assert.Equal(bits, result.EntropyBits);
            Assert.Equal(length, result.Length);
            Assert.Equal(algorithm.ToString(), result.Kind);
            Assert.Equal($"{bits}-bit HMAC key, Base64 encoded ({length} characters)", result.Composition);
        }

        [Fact]
        public void A_jwt_secret_always_says_that_an_hmac_key_can_also_mint_tokens()
        {
            var result = _generator.GenerateJwtSecret(new JwtSecretSpec());

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("symmetric", StringComparison.OrdinalIgnoreCase));

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("never put it in a token payload", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void An_undefined_jwt_algorithm_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateJwtSecret(new JwtSecretSpec { Algorithm = (JwtAlgorithm)99 }));

            Assert.Contains("HS256, HS384, HS512", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(OAuthTokenKind.AccessToken, 256)]
        [InlineData(OAuthTokenKind.RefreshToken, 512)]
        [InlineData(OAuthTokenKind.ClientSecret, 384)]
        [InlineData(OAuthTokenKind.AuthorizationCode, 256)]
        public void An_oauth_value_is_sized_for_how_long_its_kind_lives(OAuthTokenKind kind, int bits)
        {
            var result = _generator.GenerateOAuthToken(new OAuthTokenSpec { Kind = kind });

            Assert.Equal(bits, result.EntropyBits);
            Assert.Equal(kind.ToString(), result.Kind);
            Assert.Equal("Very strong", result.Strength);
        }

        [Fact]
        public void An_oauth_size_the_caller_asks_for_overrides_the_default_for_the_kind()
        {
            var result = _generator.GenerateOAuthToken(new OAuthTokenSpec
            {
                Kind = OAuthTokenKind.RefreshToken,
                Bytes = 32
            });

            Assert.Equal(256d, result.EntropyBits);
        }

        [Theory]
        [InlineData(OAuthTokenKind.AccessToken, "bearer credential")]
        [InlineData(OAuthTokenKind.RefreshToken, "rotate it on every use")]
        [InlineData(OAuthTokenKind.ClientSecret, "PKCE")]
        [InlineData(OAuthTokenKind.AuthorizationCode, "single use")]
        public void Each_oauth_kind_carries_the_advice_that_belongs_to_it(OAuthTokenKind kind, string expected)
        {
            var result = _generator.GenerateOAuthToken(new OAuthTokenSpec { Kind = kind });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains(expected, StringComparison.OrdinalIgnoreCase));

            // Every kind is also told to store a hash rather than the value itself.
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("store a hash of it", StringComparison.OrdinalIgnoreCase));
        }

        [Theory]
        [InlineData(15)]
        [InlineData(129)]
        public void An_oauth_size_outside_the_supported_range_is_refused(int bytes)
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateOAuthToken(new OAuthTokenSpec { Bytes = bytes }));
        }

        [Fact]
        public void An_undefined_oauth_kind_is_refused()
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateOAuthToken(new OAuthTokenSpec { Kind = (OAuthTokenKind)99 }));
        }

        [Fact]
        public void The_default_webauthn_values_are_a_32_byte_challenge_and_a_64_byte_user_handle()
        {
            var result = _generator.GenerateWebAuthnCredential(new WebAuthnSpec());

            Assert.Equal(32, result.ChallengeBytes);
            Assert.Equal(64, result.UserHandleBytes);
            Assert.Equal(43, result.Challenge.Length);
            Assert.Equal(86, result.UserHandle.Length);

            Assert.True(
                !string.Equals(result.Challenge, result.UserHandle, StringComparison.Ordinal),
                "The challenge and the user handle were the same value, so one of them was reused.");
        }

        [Fact]
        public void The_webauthn_values_are_base64url_so_they_survive_the_browser_json_api()
        {
            var result = _generator.GenerateWebAuthnCredential(new WebAuthnSpec());

            foreach (var value in new[] { result.Challenge, result.UserHandle })
            {
                Assert.True(
                    value.All(character => SecretText.Base64UrlAlphabet.Contains(character, StringComparison.Ordinal)),
                    "A WebAuthn value contained a character outside the URL-safe Base64 alphabet.");
            }
        }

        [Fact]
        public void A_webauthn_response_says_what_only_the_authenticator_can_provide()
        {
            var result = _generator.GenerateWebAuthnCredential(new WebAuthnSpec());

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("credential ID", StringComparison.OrdinalIgnoreCase));

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("used once", StringComparison.OrdinalIgnoreCase));

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("no personal information", StringComparison.OrdinalIgnoreCase));
        }

        [Theory]
        [InlineData(WebAuthnSpec.MinimumBytes - 1, 64)]
        [InlineData(WebAuthnSpec.MaximumBytes + 1, 64)]
        [InlineData(32, WebAuthnSpec.MinimumBytes - 1)]
        [InlineData(32, WebAuthnSpec.MaximumBytes + 1)]
        public void A_webauthn_size_outside_the_supported_range_is_refused(int challenge, int userHandle)
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateWebAuthnCredential(new WebAuthnSpec
                {
                    ChallengeBytes = challenge,
                    UserHandleBytes = userHandle
                }));
        }

        [Theory]
        [InlineData(RandomStringAlphabet.Alphanumeric, 62)]
        [InlineData(RandomStringAlphabet.Letters, 52)]
        [InlineData(RandomStringAlphabet.Lowercase, 26)]
        [InlineData(RandomStringAlphabet.Uppercase, 26)]
        [InlineData(RandomStringAlphabet.Digits, 10)]
        [InlineData(RandomStringAlphabet.Hex, 16)]
        [InlineData(RandomStringAlphabet.HexUpper, 16)]
        [InlineData(RandomStringAlphabet.Base64Url, 64)]
        public void A_random_string_uses_the_named_alphabet_and_reports_what_it_carries(
            RandomStringAlphabet alphabet,
            int alphabetSize)
        {
            var characters = SecretText.Alphabet(alphabet);

            Assert.Equal(alphabetSize, characters.Length);

            var result = _generator.GenerateRandomString(new RandomStringSpec
            {
                Length = 40,
                Alphabet = alphabet
            });

            Assert.Equal(40, result.Length);
            Assert.True(
                result.Value.All(character => characters.Contains(character, StringComparison.Ordinal)),
                "A random string contained a character from outside the alphabet that was asked for.");

            Assert.Equal(Math.Round(40 * Math.Log2(alphabetSize), 1), result.EntropyBits);
            Assert.Contains($"({alphabetSize} symbols)", result.Composition, StringComparison.Ordinal);
        }

        [Fact]
        public void A_custom_alphabet_is_the_only_thing_a_random_string_is_sampled_from()
        {
            const string alphabet = "ACEFGHJKLMNPQRTUVWXY34679";

            var spec = new RandomStringSpec
            {
                Length = 24,
                Alphabet = RandomStringAlphabet.Custom,
                CustomAlphabet = alphabet
            };

            for (var attempt = 0; attempt < Iterations; attempt++)
            {
                var value = _generator.GenerateRandomString(spec).Value;

                Assert.True(
                    value.All(character => alphabet.Contains(character, StringComparison.Ordinal)),
                    "A random string contained a character from outside the supplied alphabet.");
            }

            var result = _generator.GenerateRandomString(spec);

            Assert.Equal(Math.Round(24 * Math.Log2(alphabet.Length), 1), result.EntropyBits);

            // The alphabet is caller-supplied and could contain anything, so it is described rather than
            // echoed back.
            Assert.DoesNotContain(alphabet, result.Composition, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(RandomStringSpec.MinimumLength - 1)]
        [InlineData(-1)]
        [InlineData(RandomStringSpec.MaximumLength + 1)]
        public void A_random_string_length_outside_the_supported_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateRandomString(new RandomStringSpec { Length = length }));

            Assert.Contains("between 1 and 4096 characters", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_custom_alphabet_supplied_without_asking_for_custom_is_reported_rather_than_ignored()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateRandomString(new RandomStringSpec
                {
                    Alphabet = RandomStringAlphabet.Alphanumeric,
                    CustomAlphabet = "abc"
                }));

            Assert.Contains("Set the alphabet to 'custom'", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("")]
        [InlineData("a")]
        [InlineData("aab")]
        [InlineData("ab c")]
        [InlineData("ab\tc")]
        public void A_custom_alphabet_that_would_make_the_reported_entropy_wrong_is_refused(string alphabet)
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateRandomString(new RandomStringSpec
                {
                    Alphabet = RandomStringAlphabet.Custom,
                    CustomAlphabet = alphabet
                }));
        }

        [Fact]
        public void An_undefined_alphabet_is_refused()
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateRandomString(new RandomStringSpec
                {
                    Alphabet = (RandomStringAlphabet)99
                }));
        }

        [Fact]
        public void A_vapid_pair_is_a_p256_key_in_both_the_raw_and_the_pem_forms()
        {
            var result = _generator.GenerateVapidKey();

            Assert.Equal("P-256", result.Curve);

            var point = FromBase64Url(result.PublicKey);
            var scalar = FromBase64Url(result.PrivateKey);

            // The uncompressed point form Web Push expects: 0x04 followed by two 32 byte coordinates.
            Assert.Equal(65, point.Length);
            Assert.Equal(0x04, point[0]);
            Assert.Equal(32, scalar.Length);

            Assert.True(
                result.PublicKeyPem.StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal),
                "The public key was not exported as a SubjectPublicKeyInfo PEM.");

            // Asserted through a boolean so a failure cannot print the private key.
            Assert.True(
                result.PrivateKeyPem.StartsWith("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal),
                "The private key was not exported as a PKCS#8 PEM.");
        }

        [Fact]
        public void The_raw_vapid_form_and_the_pem_form_describe_the_same_key()
        {
            var result = _generator.GenerateVapidKey();

            var point = FromBase64Url(result.PublicKey);

            using var fromPem = ECDsa.Create();
            fromPem.ImportFromPem(result.PublicKeyPem);

            var exported = fromPem.ExportParameters(includePrivateParameters: false);

            Assert.True(
                point.AsSpan(1, 32).SequenceEqual(exported.Q.X),
                "The raw public point and the PEM public key disagreed on the X coordinate.");

            Assert.True(
                point.AsSpan(33, 32).SequenceEqual(exported.Q.Y),
                "The raw public point and the PEM public key disagreed on the Y coordinate.");
        }

        [Fact]
        public void A_vapid_pair_can_actually_sign_and_verify_an_es256_signature()
        {
            var result = _generator.GenerateVapidKey();

            // VAPID authenticates by signing a JWT with ES256, so the pair is only useful if this works.
            var message = System.Text.Encoding.UTF8.GetBytes("vapid round trip");

            using var signer = ECDsa.Create();
            signer.ImportFromPem(result.PrivateKeyPem);

            var signature = signer.SignData(message, HashAlgorithmName.SHA256);

            using var verifier = ECDsa.Create();
            verifier.ImportFromPem(result.PublicKeyPem);

            Assert.True(
                verifier.VerifyData(message, signature, HashAlgorithmName.SHA256),
                "A signature made with the VAPID private key did not verify against its public key.");

            // The raw Base64url values a Web Push library consumes must rebuild the same key.
            var point = FromBase64Url(result.PublicKey);

            using var fromRaw = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = FromBase64Url(result.PrivateKey),
                Q = new ECPoint
                {
                    X = point[1..33],
                    Y = point[33..]
                }
            });

            Assert.True(
                fromRaw.VerifyData(message, signature, HashAlgorithmName.SHA256),
                "The key rebuilt from the raw VAPID values did not match the PEM key.");
        }

        [Fact]
        public void A_vapid_response_says_which_half_is_secret_and_what_rotation_costs()
        {
            var result = _generator.GenerateVapidKey();

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("private key must stay", StringComparison.OrdinalIgnoreCase));

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("invalidates every existing push subscription", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void Independent_vapid_pairs_are_not_the_same_pair()
        {
            var first = _generator.GenerateVapidKey();
            var second = _generator.GenerateVapidKey();

            Assert.NotEqual(first.PublicKey, second.PublicKey);

            // The private halves are compared through a boolean so a failure cannot print either one.
            Assert.True(
                !string.Equals(first.PrivateKey, second.PrivateKey, StringComparison.Ordinal),
                "Two VAPID pairs shared the same private key.");
        }

        [Fact]
        public void A_machine_credential_below_128_bits_says_so_and_one_at_128_bits_does_not()
        {
            var short128 = _generator.GenerateApiKey(new ByteSecretSpec { Bytes = 16 });

            Assert.Equal(128d, short128.EntropyBits);
            Assert.Empty(short128.Warnings);

            var weaker = _generator.GenerateRandomString(new RandomStringSpec { Length = 8 });

            Assert.True(
                weaker.EntropyBits < 128d,
                "An eight character alphanumeric string was expected to fall below the machine credential threshold.");

            Assert.Contains(
                weaker.Warnings,
                warning => warning.Contains("machine credential", StringComparison.Ordinal));
        }

        [Fact]
        public void Independent_calls_do_not_repeat()
        {
            var generated = Enumerable.Range(0, Iterations)
                .Select(_ => _generator.GenerateApiKey(new ByteSecretSpec()).Value)
                .ToArray();

            // A 256 bit value repeating within 50 draws would mean the generator is not random. Only the
            // counts are asserted, so no value reaches the log.
            Assert.Equal(Iterations, generated.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public void Every_generator_refuses_a_missing_options_object()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateApiKey(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateJwtSecret(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateOAuthToken(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateWebAuthnCredential(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateRandomString(null!));
        }

        [Fact]
        public void Every_generator_reports_a_strength_label_that_matches_its_own_figure()
        {
            foreach (var result in EveryKindOfSecret())
            {
                Assert.Equal(PasswordStrength.Describe(result.EntropyBits), result.Strength);
                Assert.Equal(result.Value.Length, result.Length);
                Assert.True(result.EntropyBits > 0d, "A generated value was reported as carrying no entropy.");
            }
        }

        [Fact]
        public void No_generator_repeats_the_generated_value_in_the_text_it_returns()
        {
            foreach (var result in EveryKindOfSecret())
            {
                // The composition and the warnings are the parts a caller may safely log, so neither may
                // contain the value itself. Failures name the field rather than showing the value.
                Assert.False(
                    result.Composition.Contains(result.Value, StringComparison.OrdinalIgnoreCase),
                    "The composition description contained the generated value.");

                Assert.False(
                    result.Warnings.Any(warning => warning.Contains(result.Value, StringComparison.OrdinalIgnoreCase)),
                    "A warning contained the generated value.");
            }
        }

        /// <summary>
        /// One result from every generator that returns a <see cref="GeneratedSecret"/>, so the
        /// cross-cutting properties are checked against all of them rather than only against an API key.
        /// </summary>
        private IEnumerable<GeneratedSecret> EveryKindOfSecret()
        {
            yield return _generator.GenerateApiKey(new ByteSecretSpec());
            yield return _generator.GenerateApiKey(new ByteSecretSpec
            {
                Bytes = 16,
                Encoding = SecretEncoding.Base62,
                Prefix = "sk-test-"
            });
            yield return _generator.GenerateJwtSecret(new JwtSecretSpec());
            yield return _generator.GenerateJwtSecret(new JwtSecretSpec
            {
                Algorithm = JwtAlgorithm.HS512,
                Encoding = SecretEncoding.Hex
            });

            foreach (var kind in Enum.GetValues<OAuthTokenKind>())
            {
                yield return _generator.GenerateOAuthToken(new OAuthTokenSpec { Kind = kind });
            }

            yield return _generator.GenerateRandomString(new RandomStringSpec());

            // Short enough to carry the low-entropy advisory, long enough that the value cannot appear by
            // chance inside the description it is checked against.
            yield return _generator.GenerateRandomString(new RandomStringSpec { Length = 12 });
            yield return _generator.GenerateRandomString(new RandomStringSpec
            {
                Length = 16,
                Alphabet = RandomStringAlphabet.Custom,
                CustomAlphabet = "abcdef012345"
            });
        }

        /// <summary>
        /// Decodes an unpadded URL-safe Base64 value, so the tests can inspect the bytes behind a value
        /// rather than trusting its text form.
        /// </summary>
        /// <param name="value">The Base64url text.</param>
        private static byte[] FromBase64Url(string value)
        {
            var padded = value.Replace('-', '+').Replace('_', '/');

            padded += (padded.Length % 4) switch
            {
                2 => "==",
                3 => "=",
                _ => string.Empty
            };

            return Convert.FromBase64String(padded);
        }
    }
}
