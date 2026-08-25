using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Identity;
using SecureToolKitAPI.Cryptography.Internal;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The identity generator: that a UUID carries the version and variant markers RFC 9562 requires, that
    /// a TOTP secret is the size the chosen hash function calls for, that an enrollment URI is one an
    /// authenticator can actually read, that the codes match the vectors published in RFC 6238, and that
    /// unusable options are refused before any randomness is drawn.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A TOTP secret is a complete second factor, so no assertion prints a generated one. Sizes, alphabets
    /// and uniqueness are checked through booleans carrying a message that describes the defect rather than
    /// showing the value.
    /// </para>
    /// <para>
    /// The TOTP expectations are the vectors from RFC 6238 Appendix B, written out here as literals. That is
    /// the whole point of them: the truncation is the one piece of arithmetic this project implements
    /// itself, so it is asserted against numbers published by somebody else rather than against numbers
    /// this code produced.
    /// </para>
    /// <para>
    /// The seeds are the ones the RFC uses — ASCII digits repeated to the hash's output size. They are test
    /// vectors published in a standards document, not secrets, and they must never be used anywhere real.
    /// </para>
    /// </remarks>
    public class IdentityGeneratorTests
    {
        /// <summary>The RFC 4648 Base32 alphabet, written out so a change to the encoder fails here.</summary>
        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <summary>The hexadecimal digits a lowercase UUID may contain, plus the separator.</summary>
        private const string HexLower = "0123456789abcdef";

        /// <summary>
        /// The RFC 6238 SHA-1 seed, Base32 encoded: the 20 ASCII bytes <c>12345678901234567890</c>.
        /// </summary>
        private const string Sha1Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        /// <summary>The RFC 6238 SHA-256 seed, Base32 encoded: 32 ASCII bytes.</summary>
        private const string Sha256Seed =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

        /// <summary>The RFC 6238 SHA-512 seed, Base32 encoded: 64 ASCII bytes.</summary>
        private const string Sha512Seed =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

        /// <summary>
        /// A ten-byte secret, the smallest a supplied one may be: the ASCII digits <c>1234567890</c>.
        /// </summary>
        private const string TenByteSecret = "GEZDGNBVGY3TQOJQ";

        /// <summary>
        /// How many values the uniqueness checks draw. Enough that a generator reusing one would fail
        /// reliably, small enough to keep the suite fast.
        /// </summary>
        private const int Iterations = 50;

        private readonly IdentityGenerator _generator = new();

        [Fact]
        public void The_default_uuid_is_one_lowercase_hyphenated_version_four_value()
        {
            var result = _generator.GenerateUuids(new UuidSpec());

            Assert.Single(result.Values);
            Assert.Equal("v4", result.Version);
            Assert.Equal("hyphenated", result.Format);
            Assert.Equal(122, result.RandomBits);
            Assert.Equal("RFC 9562 version 4: 122 random bits", result.Composition);

            var value = result.Values[0];

            Assert.Equal(36, value.Length);
            Assert.True(
                value.All(character => character == '-' || HexLower.Contains(character, StringComparison.Ordinal)),
                "A UUID contained a character that is neither a lowercase hexadecimal digit nor a hyphen.");
        }

        [Theory]
        [InlineData(UuidVersion.V4, '4')]
        [InlineData(UuidVersion.V7, '7')]
        public void A_uuid_carries_the_version_nibble_and_the_rfc_variant_bits(
            UuidVersion version,
            char expected)
        {
            var result = _generator.GenerateUuids(new UuidSpec { Count = Iterations, Version = version });

            // In the canonical form the version is the first digit of the third group and the variant is
            // the first digit of the fourth, which is the layout the generator writes by hand.
            Assert.All(
                result.Values,
                value => Assert.True(
                    value[14] == expected,
                    $"A UUID did not carry the version {expected} marker in the expected position."));

            Assert.All(
                result.Values,
                value => Assert.True(
                    value[19] is '8' or '9' or 'a' or 'b',
                    "A UUID did not carry the RFC 9562 variant bits in the expected position."));
        }

        [Fact]
        public void A_version_seven_uuid_starts_with_the_current_time_and_says_what_that_discloses()
        {
            var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var result = _generator.GenerateUuids(
                new UuidSpec { Count = Iterations, Version = UuidVersion.V7, Format = UuidFormat.Compact });

            var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            Assert.Equal(74, result.RandomBits);
            Assert.Equal(
                "RFC 9562 version 7: a 48-bit millisecond timestamp followed by 74 random bits",
                result.Composition);

            // The first twelve hexadecimal digits are the 48-bit millisecond timestamp.
            Assert.All(
                result.Values,
                value =>
                {
                    var milliseconds = Convert.ToInt64(value[..12], 16);

                    Assert.True(
                        milliseconds >= before && milliseconds <= after,
                        "A version 7 UUID did not carry a timestamp from the moment it was generated.");
                });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("carries the time it was created", StringComparison.Ordinal));
        }

        [Fact]
        public void A_version_four_uuid_does_not_disclose_when_it_was_made()
        {
            var result = _generator.GenerateUuids(new UuidSpec());

            Assert.DoesNotContain(
                result.Warnings,
                warning => warning.Contains("carries the time it was created", StringComparison.Ordinal));
        }

        [Fact]
        public void Version_seven_uuids_do_not_go_backwards_in_time()
        {
            var timestamps = new List<long>();

            for (var index = 0; index < Iterations; index++)
            {
                var value = _generator
                    .GenerateUuids(
                        new UuidSpec { Version = UuidVersion.V7, Format = UuidFormat.Compact })
                    .Values[0];

                timestamps.Add(Convert.ToInt64(value[..12], 16));
            }

            // Two values drawn inside the same millisecond share a timestamp, so the guarantee is that the
            // sequence never decreases rather than that it strictly increases.
            for (var index = 1; index < timestamps.Count; index++)
            {
                Assert.True(
                    timestamps[index] >= timestamps[index - 1],
                    "A version 7 UUID carried an earlier timestamp than the one generated before it.");
            }
        }

        [Theory]
        [InlineData(UuidFormat.Hyphenated, 36, "hyphenated")]
        [InlineData(UuidFormat.Compact, 32, "compact")]
        [InlineData(UuidFormat.Braced, 38, "braced")]
        [InlineData(UuidFormat.Urn, 45, "urn")]
        public void Each_format_is_written_at_its_own_length_and_named_in_the_response(
            UuidFormat format,
            int expectedLength,
            string expectedName)
        {
            var result = _generator.GenerateUuids(new UuidSpec { Format = format });
            var value = result.Values[0];

            Assert.Equal(expectedName, result.Format);
            Assert.Equal(expectedLength, value.Length);

            switch (format)
            {
                case UuidFormat.Compact:
                    Assert.False(
                        value.Contains('-', StringComparison.Ordinal),
                        "A compact UUID contained a hyphen.");
                    break;
                case UuidFormat.Braced:
                    Assert.StartsWith("{", value, StringComparison.Ordinal);
                    Assert.EndsWith("}", value, StringComparison.Ordinal);
                    break;
                case UuidFormat.Urn:
                    Assert.StartsWith("urn:uuid:", value, StringComparison.Ordinal);
                    break;
                default:
                    Assert.Equal(4, value.Count(character => character == '-'));
                    break;
            }
        }

        [Fact]
        public void An_uppercase_uuid_uses_uppercase_hexadecimal_and_keeps_its_markers()
        {
            var result = _generator.GenerateUuids(new UuidSpec { Count = Iterations, Uppercase = true });

            Assert.All(
                result.Values,
                value => Assert.True(
                    value.All(character =>
                        character == '-'
                        || char.IsAsciiDigit(character)
                        || character is >= 'A' and <= 'F'),
                    "An uppercase UUID contained a character outside the uppercase hexadecimal digits."));

            Assert.All(
                result.Values,
                value => Assert.True(
                    value[14] == '4' && value[19] is '8' or '9' or 'A' or 'B',
                    "An uppercase UUID lost its version or variant markers."));
        }

        [Fact]
        public void Every_uuid_in_a_batch_is_distinct()
        {
            var result = _generator.GenerateUuids(new UuidSpec { Count = UuidSpec.MaximumCount });

            Assert.Equal(UuidSpec.MaximumCount, result.Values.Count);
            Assert.True(
                result.Values.Distinct(StringComparer.Ordinal).Count() == result.Values.Count,
                "A batch of UUIDs contained the same value twice.");
        }

        [Fact]
        public void A_uuid_says_it_is_an_identifier_rather_than_a_credential()
        {
            var result = _generator.GenerateUuids(new UuidSpec());

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("not a credential", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(UuidSpec.MaximumCount + 1)]
        public void A_uuid_count_outside_the_supported_range_is_refused(int count)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateUuids(new UuidSpec { Count = count }));

            Assert.Contains("between 1 and 100", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_undefined_uuid_version_or_format_is_refused()
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateUuids(new UuidSpec { Version = (UuidVersion)7 }));

            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateUuids(new UuidSpec { Format = (UuidFormat)9 }));
        }

        [Fact]
        public void The_default_totp_secret_is_a_hundred_and_sixty_bit_sha1_secret_for_six_digit_codes()
        {
            var result = _generator.GenerateTotpSecret(new TotpSecretSpec());

            Assert.Equal(20, result.Bytes);
            Assert.Equal(160d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal("SHA1", result.Algorithm);
            Assert.Equal(6, result.Digits);
            Assert.Equal(30, result.PeriodSeconds);
            Assert.Equal(
                "160 random bits, Base32 encoded for HMAC-SHA1, 6 digit codes, 30 second time step",
                result.Composition);
        }

        [Theory]
        [InlineData(TotpAlgorithm.Sha1, 20, "SHA1")]
        [InlineData(TotpAlgorithm.Sha256, 32, "SHA256")]
        [InlineData(TotpAlgorithm.Sha512, 64, "SHA512")]
        public void A_totp_secret_defaults_to_the_size_recommended_for_its_hash_function(
            TotpAlgorithm algorithm,
            int expectedBytes,
            string expectedName)
        {
            var result = _generator.GenerateTotpSecret(
                new TotpSecretSpec { Parameters = new TotpParameters { Algorithm = algorithm } });

            Assert.Equal(expectedBytes, result.Bytes);
            Assert.Equal(expectedName, result.Algorithm);

            Assert.True(
                Base32Text.TryDecode(result.Secret, out var key),
                "A generated TOTP secret was not valid Base32.");
            Assert.True(
                key.Length == expectedBytes,
                "A generated TOTP secret decoded to a different size than the response reported.");
        }

        [Fact]
        public void A_generated_totp_secret_is_unpadded_base32_an_authenticator_can_read()
        {
            var result = _generator.GenerateTotpSecret(new TotpSecretSpec());

            Assert.True(
                result.Secret.All(character => Base32Alphabet.Contains(character, StringComparison.Ordinal)),
                "A generated TOTP secret contained a character outside the RFC 4648 alphabet.");
            Assert.True(
                !result.Secret.Contains('=', StringComparison.Ordinal),
                "A generated TOTP secret carried Base32 padding, which an otpauth URI does not use.");
        }

        [Fact]
        public void Every_generated_totp_secret_is_distinct()
        {
            var secrets = new HashSet<string>(StringComparer.Ordinal);

            for (var index = 0; index < Iterations; index++)
            {
                Assert.True(
                    secrets.Add(_generator.GenerateTotpSecret(new TotpSecretSpec()).Secret),
                    "The same TOTP secret was generated twice.");
            }
        }

        [Fact]
        public void A_totp_secret_says_it_is_the_whole_second_factor_and_is_returned_once()
        {
            var result = _generator.GenerateTotpSecret(new TotpSecretSpec());

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("entire second factor", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("returned once", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("rate-limit", StringComparison.Ordinal));
        }

        [Fact]
        public void A_totp_secret_warns_when_its_parameters_are_not_the_universally_supported_ones()
        {
            var result = _generator.GenerateTotpSecret(
                new TotpSecretSpec
                {
                    Bytes = 16,
                    Parameters = new TotpParameters
                    {
                        Algorithm = TotpAlgorithm.Sha512,
                        Digits = 8,
                        PeriodSeconds = 60
                    }
                });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Confirm yours supports SHA512", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("8 digit codes are not universally supported", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("60 second period", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("128 bits is below the 160", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(TotpSecretSpec.MinimumBytes - 1)]
        [InlineData(TotpSecretSpec.MaximumBytes + 1)]
        [InlineData(0)]
        public void A_totp_secret_size_outside_the_supported_range_is_refused(int bytes)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateTotpSecret(new TotpSecretSpec { Bytes = bytes }));

            Assert.Contains("between 16 and 64 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(5)]
        [InlineData(9)]
        public void A_digit_count_outside_what_the_truncation_can_give_is_refused(int digits)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateTotpSecret(
                    new TotpSecretSpec { Parameters = new TotpParameters { Digits = digits } }));

            Assert.Contains("between 6 and 8", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(14)]
        [InlineData(301)]
        public void A_period_outside_the_supported_range_is_refused(int periodSeconds)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateTotpSecret(
                    new TotpSecretSpec { Parameters = new TotpParameters { PeriodSeconds = periodSeconds } }));

            Assert.Contains("between 15 and 300 seconds", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_undefined_totp_algorithm_is_refused_and_the_message_lists_the_supported_ones()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateTotpSecret(
                    new TotpSecretSpec
                    {
                        Parameters = new TotpParameters { Algorithm = (TotpAlgorithm)6 }
                    }));

            Assert.Contains("SHA1, SHA256, SHA512", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_enrollment_produces_a_uri_an_authenticator_can_read()
        {
            var result = _generator.CreateTotpEnrollment(
                new TotpEnrollmentSpec { Issuer = "Example Corp", Account = "person@example.com" });

            Assert.Equal("Example Corp", result.Issuer);
            Assert.Equal("person@example.com", result.Account);
            Assert.Equal(20, result.Bytes);
            Assert.Equal("SHA1", result.Algorithm);
            Assert.Equal("otpauth URI for HMAC-SHA1, 6 digit codes, 30 second time step", result.Composition);

            // The space and the at sign have to be percent-encoded or the label parses somewhere else.
            Assert.StartsWith(
                "otpauth://totp/Example%20Corp:person%40example.com?secret=",
                result.Uri,
                StringComparison.Ordinal);
            Assert.Contains("&issuer=Example%20Corp", result.Uri, StringComparison.Ordinal);
            Assert.Contains("&algorithm=SHA1", result.Uri, StringComparison.Ordinal);
            Assert.Contains("&digits=6", result.Uri, StringComparison.Ordinal);
            Assert.Contains("&period=30", result.Uri, StringComparison.Ordinal);

            Assert.True(
                result.Uri.Contains($"secret={result.Secret}", StringComparison.Ordinal),
                "The enrollment URI did not carry the secret it was built around.");
        }

        [Fact]
        public void An_enrollment_says_the_uri_is_a_picture_of_the_second_factor()
        {
            var result = _generator.CreateTotpEnrollment(
                new TotpEnrollmentSpec { Issuer = "Example Corp", Account = "person@example.com" });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("picture of the second factor", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Confirm one code", StringComparison.Ordinal));
        }

        [Fact]
        public void An_enrollment_normalises_a_supplied_secret_to_the_canonical_form()
        {
            var result = _generator.CreateTotpEnrollment(
                new TotpEnrollmentSpec
                {
                    Issuer = "Example",
                    Account = "person",

                    // The same ten bytes, written the way a person reads a secret back over the phone.
                    Secret = "gezd-gnbv-gy3t-qojq"
                });

            Assert.Equal(TenByteSecret, result.Secret);
            Assert.Equal(10, result.Bytes);
            Assert.Contains($"secret={TenByteSecret}", result.Uri, StringComparison.Ordinal);
        }

        [Fact]
        public void An_enrollment_trims_the_labels_it_was_given()
        {
            var result = _generator.CreateTotpEnrollment(
                new TotpEnrollmentSpec { Issuer = "  Example  ", Account = "  person  " });

            Assert.Equal("Example", result.Issuer);
            Assert.Equal("person", result.Account);
            Assert.StartsWith("otpauth://totp/Example:person?", result.Uri, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("", "person", "issuer")]
        [InlineData("   ", "person", "issuer")]
        [InlineData("Example", "", "account name")]
        [InlineData("Example", "   ", "account name")]
        public void An_enrollment_without_a_label_is_refused(string issuer, string account, string expected)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.CreateTotpEnrollment(
                    new TotpEnrollmentSpec { Issuer = issuer, Account = account }));

            Assert.Equal($"The {expected} is required.", exception.Message);
        }

        [Fact]
        public void A_label_containing_a_colon_is_refused_because_it_would_split_the_uri()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.CreateTotpEnrollment(
                    new TotpEnrollmentSpec { Issuer = "Example:Corp", Account = "person" }));

            Assert.Equal("The issuer must not contain a colon.", exception.Message);
        }

        [Fact]
        public void A_label_that_is_too_long_or_carries_a_control_character_is_refused()
        {
            var tooLong = new string('a', TotpEnrollmentSpec.MaximumLabelLength + 1);

            Assert.Contains(
                "at most 64 characters",
                Assert.Throws<CryptographicRequestException>(
                    () => _generator.CreateTotpEnrollment(
                        new TotpEnrollmentSpec { Issuer = tooLong, Account = "person" })).Message,
                StringComparison.Ordinal);

            Assert.Contains(
                "control characters",
                Assert.Throws<CryptographicRequestException>(
                    () => _generator.CreateTotpEnrollment(
                        new TotpEnrollmentSpec { Issuer = "Example", Account = "person\n" })).Message,
                StringComparison.Ordinal);
        }

        [Fact]
        public void An_enrollment_given_both_a_secret_and_a_size_is_refused_rather_than_ignoring_one()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.CreateTotpEnrollment(
                    new TotpEnrollmentSpec
                    {
                        Issuer = "Example",
                        Account = "person",
                        Secret = Sha1Seed,
                        Bytes = 32
                    }));

            Assert.Contains(
                "Omit the size to use the supplied secret",
                exception.Message,
                StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(Rfc6238EightDigitVectors))]
        public void An_eight_digit_code_matches_the_rfc_6238_vectors(
            long unixTimeSeconds,
            TotpAlgorithm algorithm,
            string secret,
            string expected)
        {
            var result = _generator.ComputeTotpCode(
                new TotpCodeSpec
                {
                    Secret = secret,
                    UnixTimeSeconds = unixTimeSeconds,
                    Parameters = new TotpParameters { Algorithm = algorithm, Digits = 8 }
                });

            Assert.Equal(expected, result.Code);
            Assert.Equal(unixTimeSeconds, result.UnixTimeSeconds);
            Assert.Equal(unixTimeSeconds / 30, result.Counter);
        }

        /// <summary>
        /// The RFC 6238 Appendix B table: six moments against each of the three hash functions, with the
        /// seed the RFC specifies for each.
        /// </summary>
        public static TheoryData<long, TotpAlgorithm, string, string> Rfc6238EightDigitVectors => new()
        {
            { 59L, TotpAlgorithm.Sha1, Sha1Seed, "94287082" },
            { 59L, TotpAlgorithm.Sha256, Sha256Seed, "46119246" },
            { 59L, TotpAlgorithm.Sha512, Sha512Seed, "90693936" },
            { 1111111109L, TotpAlgorithm.Sha1, Sha1Seed, "07081804" },
            { 1111111109L, TotpAlgorithm.Sha256, Sha256Seed, "68084774" },
            { 1111111109L, TotpAlgorithm.Sha512, Sha512Seed, "25091201" },
            { 1111111111L, TotpAlgorithm.Sha1, Sha1Seed, "14050471" },
            { 1111111111L, TotpAlgorithm.Sha256, Sha256Seed, "67062674" },
            { 1111111111L, TotpAlgorithm.Sha512, Sha512Seed, "99943326" },
            { 1234567890L, TotpAlgorithm.Sha1, Sha1Seed, "89005924" },
            { 1234567890L, TotpAlgorithm.Sha256, Sha256Seed, "91819424" },
            { 1234567890L, TotpAlgorithm.Sha512, Sha512Seed, "93441116" },
            { 2000000000L, TotpAlgorithm.Sha1, Sha1Seed, "69279037" },
            { 2000000000L, TotpAlgorithm.Sha256, Sha256Seed, "90698825" },
            { 2000000000L, TotpAlgorithm.Sha512, Sha512Seed, "38618901" },
            { 20000000000L, TotpAlgorithm.Sha1, Sha1Seed, "65353130" },
            { 20000000000L, TotpAlgorithm.Sha256, Sha256Seed, "77737706" },
            { 20000000000L, TotpAlgorithm.Sha512, Sha512Seed, "47863826" }
        };

        [Theory]
        [InlineData(59L, "287082", 1L, 1)]
        [InlineData(1111111109L, "081804", 37037036L, 1)]
        [InlineData(1111111111L, "050471", 37037037L, 29)]
        [InlineData(1234567890L, "005924", 41152263L, 30)]
        [InlineData(2000000000L, "279037", 66666666L, 10)]
        public void A_six_digit_code_is_the_low_six_digits_of_the_same_truncation(
            long unixTimeSeconds,
            string expected,
            long expectedCounter,
            int expectedValidFor)
        {
            var result = _generator.ComputeTotpCode(
                new TotpCodeSpec { Secret = Sha1Seed, UnixTimeSeconds = unixTimeSeconds });

            Assert.Equal(expected, result.Code);
            Assert.Equal(expectedCounter, result.Counter);
            Assert.Equal(expectedValidFor, result.ValidForSeconds);
            Assert.Equal("SHA1", result.Algorithm);
            Assert.Equal(6, result.Digits);
            Assert.Equal(30, result.PeriodSeconds);
            Assert.Equal(
                $"RFC 6238 code for counter {expectedCounter} using HMAC-SHA1, 6 digit codes, "
                + "30 second time step",
                result.Composition);
        }

        [Fact]
        public void A_code_is_computed_for_now_when_no_time_was_given()
        {
            var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            var result = _generator.ComputeTotpCode(new TotpCodeSpec { Secret = Sha1Seed });

            var after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            Assert.True(
                result.UnixTimeSeconds >= before && result.UnixTimeSeconds <= after,
                "A code was not computed for the moment it was asked for.");
            Assert.Equal(result.UnixTimeSeconds / 30, result.Counter);
            Assert.InRange(result.ValidForSeconds, 1, 30);
        }

        [Fact]
        public void A_code_is_padded_to_the_requested_width()
        {
            // This counter truncates to a value with a leading zero at six digits, which is the case a
            // caller comparing strings would get wrong if the padding were dropped.
            var result = _generator.ComputeTotpCode(
                new TotpCodeSpec { Secret = Sha1Seed, UnixTimeSeconds = 1234567890L });

            Assert.Equal("005924", result.Code);
            Assert.Equal(6, result.Code.Length);
        }

        [Fact]
        public void A_code_says_it_verifies_nothing()
        {
            var result = _generator.ComputeTotpCode(new TotpCodeSpec { Secret = Sha1Seed });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("verifies nothing and authenticates nobody", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("fixed-time comparison", StringComparison.Ordinal));
        }

        [Fact]
        public void A_code_response_does_not_echo_the_secret_it_was_computed_from()
        {
            var result = _generator.ComputeTotpCode(new TotpCodeSpec { Secret = Sha1Seed });

            var everything = new List<string> { result.Code, result.Composition, result.Algorithm };
            everything.AddRange(result.Warnings);

            Assert.False(
                string.Join("\n", everything).Contains(Sha1Seed, StringComparison.OrdinalIgnoreCase),
                "A code response repeated the secret it was computed from.");
        }

        [Fact]
        public void A_missing_secret_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeTotpCode(new TotpCodeSpec()));

            Assert.Equal("The secret is required.", exception.Message);
        }

        [Theory]
        [InlineData("MZXW6YTB1")]
        [InlineData("not base32 at all!")]
        [InlineData("A")]
        [InlineData("GEZDGNBVGY3TQOJQAAA")]
        public void A_secret_that_is_not_valid_base32_is_refused_without_repeating_it(string secret)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeTotpCode(new TotpCodeSpec { Secret = secret }));

            Assert.Equal("The secret is not valid Base32.", exception.Message);
        }

        [Fact]
        public void A_secret_that_decodes_below_the_rfc_floor_is_refused()
        {
            // "MZXW6YTBOI======" is six bytes, well under the eighty bits RFC 4226 requires.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeTotpCode(new TotpCodeSpec { Secret = "MZXW6YTBOI======" }));

            Assert.Contains("at least 10 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_secret_larger_than_the_request_limit_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeTotpCode(
                    new TotpCodeSpec { Secret = new string('A', 256) }));

            Assert.Contains("at most 128 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_negative_time_is_refused_rather_than_answered()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeTotpCode(
                    new TotpCodeSpec { Secret = Sha1Seed, UnixTimeSeconds = -1 }));

            Assert.Equal("The time must not be negative.", exception.Message);
        }

        [Fact]
        public void The_secret_endpoint_and_the_code_endpoint_agree_with_each_other()
        {
            var secret = _generator.GenerateTotpSecret(new TotpSecretSpec()).Secret;

            var first = _generator.ComputeTotpCode(
                new TotpCodeSpec { Secret = secret, UnixTimeSeconds = 1_700_000_000 });

            // The same secret, written the way a person would read it back, must produce the same code.
            var second = _generator.ComputeTotpCode(
                new TotpCodeSpec
                {
                    Secret = string.Join('-', Enumerable.Range(0, secret.Length / 4)
                        .Select(index => secret.Substring(index * 4, 4)))
                        .ToLowerInvariant(),
                    UnixTimeSeconds = 1_700_000_000
                });

            Assert.Equal(first.Code, second.Code);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public void Base32_encoding_matches_the_rfc_4648_vectors(string text, string expected)
        {
            var result = _generator.EncodeBase32(new Base32Spec { Text = text });

            Assert.Equal(expected, result.Value);
            Assert.Equal("Base32 (RFC 4648)", result.Encoding);
            Assert.Equal(text.Length, result.Bytes);
            Assert.Equal(expected.Length, result.Length);
        }

        [Fact]
        public void Base32_encoding_can_drop_the_padding_and_lower_the_case()
        {
            var result = _generator.EncodeBase32(
                new Base32Spec { Text = "foobar", Padding = false, Lowercase = true });

            Assert.Equal("mzxw6ytboi", result.Value);
            Assert.Equal(6, result.Bytes);
            Assert.Equal("6 bytes as unpadded, lowercase Base32", result.Composition);
        }

        [Fact]
        public void Base32_encoding_accepts_bytes_as_base64_for_input_that_is_not_text()
        {
            // "Zm9vYmFy" is "foobar", which lets the two ways of supplying input be compared directly.
            var result = _generator.EncodeBase32(new Base32Spec { Base64 = "Zm9vYmFy" });

            Assert.Equal("MZXW6YTBOI======", result.Value);
            Assert.Equal(6, result.Bytes);
        }

        [Fact]
        public void Base32_encoding_always_says_it_is_not_encryption()
        {
            var result = _generator.EncodeBase32(new Base32Spec { Text = "anything" });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("an encoding, not encryption", StringComparison.Ordinal));
        }

        [Fact]
        public void Base32_encoding_refuses_both_inputs_and_refuses_neither()
        {
            Assert.Equal(
                "Supply either text or Base64 bytes, not both.",
                Assert.Throws<CryptographicRequestException>(
                    () => _generator.EncodeBase32(new Base32Spec { Text = "a", Base64 = "YQ==" })).Message);

            Assert.Equal(
                "Either text or Base64 bytes are required.",
                Assert.Throws<CryptographicRequestException>(
                    () => _generator.EncodeBase32(new Base32Spec())).Message);
        }

        [Fact]
        public void Base32_encoding_refuses_malformed_base64_as_a_bad_request()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.EncodeBase32(new Base32Spec { Base64 = "not valid base64!" }));

            Assert.Equal("The supplied bytes are not valid Base64.", exception.Message);
        }

        [Fact]
        public void Base32_encoding_refuses_an_input_larger_than_the_limit()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.EncodeBase32(
                    new Base32Spec { Text = new string('a', Base32Spec.MaximumBytes + 1) }));

            Assert.Contains("At most 4096 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Every_operation_refuses_a_null_options_object()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateUuids(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateTotpSecret(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.CreateTotpEnrollment(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.ComputeTotpCode(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.EncodeBase32(null!));
        }
    }
}
