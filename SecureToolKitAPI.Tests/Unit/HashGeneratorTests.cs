using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Hashing;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The hash generator: that each function produces the digest the standard that defines it says it should,
    /// that the message is read as the bytes the caller said it was, that the renderings are the same digest
    /// written differently, and that the response says plainly that a hash is not encryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The digests here are known-answer vectors, not values recorded from this implementation. They come from
    /// the published test vectors for each function and were checked independently before being written down,
    /// which is what makes them worth asserting: a test that hashed a message and compared the result against
    /// whatever this code produced would agree with any mistake this code made. The empty-input and
    /// <c>"abc"</c> digests are the vectors in FIPS 180-4 and RFC 1321; the rest are the digests <c>sha256sum</c>
    /// and <c>md5sum</c> print for the same bytes.
    /// </para>
    /// <para>
    /// Nothing in this file is secret. A digest reveals nothing about its message and the messages here are
    /// literals from a specification, so values may appear freely in failure output — which is why the
    /// assertions read as plain equality rather than the boolean-with-a-message form the key and secret tests
    /// use.
    /// </para>
    /// </remarks>
    public class HashGeneratorTests
    {
        /// <summary>Advisories that belong on every digest whatever function produced it.</summary>
        private const int UniversalWarningCount = 3;

        /// <summary>Advisories on an MD5 digest: the universal ones plus the two about MD5 itself.</summary>
        private const int Md5WarningCount = UniversalWarningCount + 2;

        private readonly HashGenerator _generator = new();

        [Theory]

        // The empty string. A well-defined digest for every one of these functions, and the vector most often
        // got wrong by an implementation that mishandles the final padding block.
        [InlineData(HashAlgorithmChoice.Md5, "", "d41d8cd98f00b204e9800998ecf8427e")]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
        [InlineData(
            HashAlgorithmChoice.Sha384,
            "",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")]
        [InlineData(
            HashAlgorithmChoice.Sha512,
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
            + "63b931bd47417a81a538327af927da3e")]

        // "abc": the one-block vector printed in FIPS 180-4 and RFC 1321.
        [InlineData(HashAlgorithmChoice.Md5, "abc", "900150983cd24fb0d6963f7d28e17f72")]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
        [InlineData(
            HashAlgorithmChoice.Sha384,
            "abc",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")]
        [InlineData(
            HashAlgorithmChoice.Sha512,
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
            + "454d4423643ce80e2a9ac94fa54ca49f")]

        // "hello world": not from a standard, but the digest every checksum tool prints for it, so it ties this
        // implementation to what a caller would compute on their own machine.
        [InlineData(HashAlgorithmChoice.Md5, "hello world", "5eb63bbbe01eeed093cb22bb8f5acdc3")]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            "hello world",
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")]
        [InlineData(
            HashAlgorithmChoice.Sha384,
            "hello world",
            "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd")]
        [InlineData(
            HashAlgorithmChoice.Sha512,
            "hello world",
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cf"
            + "d830e81f605dcf7dc5542e93ae9cd76f")]
        public void Each_function_produces_the_digest_its_standard_says_it_should(
            HashAlgorithmChoice algorithm,
            string message,
            string expected)
        {
            var result = _generator.ComputeHash(
                new HashSpec { Algorithm = algorithm, Message = message });

            Assert.Equal(expected, result.Digest);
            Assert.Equal(expected.Length * 4, result.DigestSizeBits);
            Assert.Equal(message.Length, result.InputByteCount);
        }

        [Fact]
        public void An_empty_message_is_hashed_rather_than_refused()
        {
            // Empty and missing are different things. There is a well-known digest of nothing, so refusing to
            // compute it would be refusing a valid question.
            var result = _generator.ComputeHash(new HashSpec { Message = string.Empty });

            Assert.Equal(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                result.Digest);
            Assert.Equal(0, result.InputByteCount);
            Assert.Equal(
                "SHA-256 digest of 0 bytes of UTF-8 text, 256 bits written as lowercase hexadecimal "
                + "(64 characters)",
                result.Composition);
        }

        [Theory]
        [InlineData(HashAlgorithmChoice.Md5, "600d8b975d8f8e643bd18673ef904436")]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            "c782a94468b31a3adcfc0c8ba3cfaedc934dac022f8e99b12c22eba80626f2c5")]
        [InlineData(
            HashAlgorithmChoice.Sha384,
            "23f96ae978433e2e13f739b84162e428e6cd8135e860406fb8bb6af3a0b298b967fa3e772f471076713d7ece6d0d9a8a")]
        [InlineData(
            HashAlgorithmChoice.Sha512,
            "e49200221e2a7760edc57fea1867b05bde598f336f883a9b842b60a0da5d2b6c36fa7f531a865f1e4d25cd5d4b564d91"
            + "3fcf1d3cd4629e564c28adcc84bd5370")]
        public void Bytes_that_are_not_text_are_hashed_as_the_bytes_they_are(
            HashAlgorithmChoice algorithm,
            string expected)
        {
            // 00 ff 10 80 7f: a null, a byte that is not valid UTF-8 on its own, and a control character. This
            // is the case the input format exists for — none of these bytes survives being treated as text, so
            // without a bytes-in mode a file checksum could not be reproduced at all.
            var result = _generator.ComputeHash(new HashSpec
            {
                Algorithm = algorithm,
                InputFormat = HashInputFormat.Base64,
                Message = "AP8QgH8="
            });

            Assert.Equal(expected, result.Digest);
            Assert.Equal(5, result.InputByteCount);
            Assert.Equal("Base64 decoded input", result.InputFormat);
        }

        [Fact]
        public void The_same_bytes_hash_the_same_whether_they_arrive_as_base64_or_as_hexadecimal()
        {
            var viaBase64 = _generator.ComputeHash(new HashSpec
            {
                InputFormat = HashInputFormat.Base64,
                Message = "AP8QgH8="
            });

            var viaHex = _generator.ComputeHash(new HashSpec
            {
                InputFormat = HashInputFormat.Hex,
                Message = "00ff10807f"
            });

            Assert.Equal(viaBase64.Digest, viaHex.Digest);
            Assert.Equal(viaBase64.InputByteCount, viaHex.InputByteCount);

            // The digest is the same but the response says how the message arrived, because that is what a
            // caller needs in order to reproduce it.
            Assert.Equal("hexadecimal decoded input", viaHex.InputFormat);
        }

        [Theory]
        [InlineData("00ff10807f")]
        [InlineData("00FF10807F")]
        [InlineData("00Ff10807f")]
        [InlineData("  00ff10807f  ")]
        public void Hexadecimal_input_is_read_regardless_of_case_or_surrounding_space(string message)
        {
            var result = _generator.ComputeHash(new HashSpec
            {
                InputFormat = HashInputFormat.Hex,
                Message = message
            });

            Assert.Equal(
                "c782a94468b31a3adcfc0c8ba3cfaedc934dac022f8e99b12c22eba80626f2c5",
                result.Digest);
            Assert.Equal(5, result.InputByteCount);
        }

        [Fact]
        public void Text_is_committed_to_utf8_rather_than_left_to_the_platform()
        {
            // "caf" followed by e-acute. Built from a character code rather than written literally so the
            // encoding of this source file cannot change what is being tested.
            var message = "caf" + (char)0x00E9;

            var asText = _generator.ComputeHash(new HashSpec { Message = message });

            // The same characters as their UTF-8 bytes: 63 61 66 c3 a9. If the two agree, the text path
            // encoded as UTF-8; if the implementation had used UTF-16 the digest would be
            // 8c9f3eed8d0b4c75bdde53bf22d847cb5a1b1318e9d5ce0186142c5602ca9baa instead.
            var asBytes = _generator.ComputeHash(new HashSpec
            {
                InputFormat = HashInputFormat.Hex,
                Message = "636166c3a9"
            });

            Assert.Equal(
                "850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e",
                asText.Digest);
            Assert.Equal(asBytes.Digest, asText.Digest);

            // Four characters, five bytes. The count reported is the count that was hashed.
            Assert.Equal(4, message.Length);
            Assert.Equal(5, asText.InputByteCount);
        }

        [Theory]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            DigestEncoding.Hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            DigestEncoding.HexUpper,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
        [InlineData(
            HashAlgorithmChoice.Sha256,
            DigestEncoding.Base64,
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")]
        [InlineData(HashAlgorithmChoice.Md5, DigestEncoding.Hex, "900150983cd24fb0d6963f7d28e17f72")]
        [InlineData(HashAlgorithmChoice.Md5, DigestEncoding.HexUpper, "900150983CD24FB0D6963F7D28E17F72")]
        [InlineData(HashAlgorithmChoice.Md5, DigestEncoding.Base64, "kAFQmDzST7DWlj99KOF/cg==")]
        public void The_renderings_are_the_same_digest_written_differently(
            HashAlgorithmChoice algorithm,
            DigestEncoding encoding,
            string expected)
        {
            var result = _generator.ComputeHash(new HashSpec
            {
                Algorithm = algorithm,
                Encoding = encoding,
                Message = "abc"
            });

            Assert.Equal(expected, result.Digest);

            // The digest size is a property of the function, so it must not change with how the bytes are
            // written down.
            Assert.Equal(algorithm is HashAlgorithmChoice.Md5 ? 128 : 256, result.DigestSizeBits);
        }

        [Fact]
        public void Base64_is_standard_rather_than_url_safe_so_it_matches_a_content_digest_header()
        {
            // Standard Base64 with padding, because that is what Subresource Integrity and Content-Digest
            // carry. A URL-safe variant here would silently fail to match either.
            var result = _generator.ComputeHash(new HashSpec
            {
                Encoding = DigestEncoding.Base64,
                Message = "hello world"
            });

            Assert.Equal("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", result.Digest);
            Assert.True(
                result.Digest.EndsWith('='),
                "The Base64 digest was unpadded, so it would not match a Content-Digest header.");
        }

        [Theory]
        [InlineData(HashAlgorithmChoice.Sha256, "SHA-256", 256, 64)]
        [InlineData(HashAlgorithmChoice.Sha384, "SHA-384", 384, 96)]
        [InlineData(HashAlgorithmChoice.Sha512, "SHA-512", 512, 128)]
        [InlineData(HashAlgorithmChoice.Md5, "MD5", 128, 32)]
        public void The_reported_name_and_size_match_the_digest_that_came_back(
            HashAlgorithmChoice algorithm,
            string expectedName,
            int expectedBits,
            int expectedHexLength)
        {
            var result = _generator.ComputeHash(
                new HashSpec { Algorithm = algorithm, Message = "hello world" });

            Assert.Equal(expectedName, result.Algorithm);
            Assert.Equal(expectedBits, result.DigestSizeBits);

            // A reported size that disagreed with the digest actually returned would be worse than no size at
            // all, so the two are checked against each other: two hex characters per byte.
            Assert.Equal(expectedHexLength, result.Digest.Length);
            Assert.Equal(expectedBits, result.Digest.Length * 4);

            // The name that comes back is a name that can be sent back in, which is what makes a response
            // usable as the input to a second request.
            Assert.Equal(algorithm, HashOptions.ParseAlgorithm(result.Algorithm));
        }

        [Fact]
        public void The_same_message_always_gives_the_same_digest()
        {
            // This is the defining property of a hash and the reason it is not encryption: there is no key and
            // no randomness, so two callers hashing the same thing get the same answer. It is also exactly why
            // a digest of something guessable hides nothing.
            var first = _generator.ComputeHash(new HashSpec { Message = "hello world" });
            var second = new HashGenerator().ComputeHash(new HashSpec { Message = "hello world" });

            Assert.Equal(first.Digest, second.Digest);
        }

        [Fact]
        public void A_single_bit_of_difference_changes_the_whole_digest()
        {
            var first = _generator.ComputeHash(new HashSpec { Message = "hello world" });
            var second = _generator.ComputeHash(new HashSpec { Message = "hello worle" });

            Assert.NotEqual(first.Digest, second.Digest);

            // Not one character in common at the same position, which is what avalanche means in practice.
            var shared = first.Digest.Where((character, index) => character == second.Digest[index]).Count();

            Assert.True(
                shared < first.Digest.Length / 2,
                $"Changing one character left {shared} of {first.Digest.Length} digest positions unchanged.");
        }

        [Theory]
        [InlineData(HashAlgorithmChoice.Sha256)]
        [InlineData(HashAlgorithmChoice.Sha384)]
        [InlineData(HashAlgorithmChoice.Sha512)]
        public void A_sound_function_is_not_flagged_as_broken(HashAlgorithmChoice algorithm)
        {
            var result = _generator.ComputeHash(
                new HashSpec { Algorithm = algorithm, Message = "hello world" });

            Assert.False(result.IsCryptographicallyBroken);
            Assert.Equal(UniversalWarningCount, result.Warnings.Count);
        }

        [Fact]
        public void Md5_is_flagged_as_broken_and_says_what_it_may_still_be_used_for()
        {
            var result = _generator.ComputeHash(
                new HashSpec { Algorithm = HashAlgorithmChoice.Md5, Message = "hello world" });

            Assert.True(result.IsCryptographicallyBroken);
            Assert.Equal(Md5WarningCount, result.Warnings.Count);

            // The broken-function advisory comes first, so a caller who reads one line reads the one that
            // applies to the digest they are holding.
            Assert.StartsWith("MD5 is cryptographically broken.", result.Warnings[0], StringComparison.Ordinal);

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Never use it for a signature", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Prefer SHA-256", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(HashAlgorithmChoice.Sha256)]
        [InlineData(HashAlgorithmChoice.Sha512)]
        [InlineData(HashAlgorithmChoice.Md5)]
        public void Every_response_says_that_hashing_is_not_encryption(HashAlgorithmChoice algorithm)
        {
            var result = _generator.ComputeHash(
                new HashSpec { Algorithm = algorithm, Message = "hello world" });

            // The three confusions this endpoint has to head off, on every response and not only on the broken
            // function: that a digest hides the message, that a fast hash can store a password, and that a
            // digest says who produced the data.
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("A hash is not encryption.", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Never store a password", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Argon2", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("does not show who produced it", StringComparison.Ordinal));

            // The advisories point at the endpoints that do the jobs a hash cannot, rather than only saying
            // what not to do.
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("/api/signature/hmac-sha256", StringComparison.Ordinal));
        }

        [Fact]
        public void The_message_is_never_part_of_the_response()
        {
            // The message may well be a secret the caller is fingerprinting, so it is counted and dropped. A
            // digest that came back alongside its own input would turn a safe operation into a leak.
            const string message = "correct-horse-battery-staple-do-not-echo-this";

            var result = _generator.ComputeHash(new HashSpec { Message = message });

            var fields = new (string Field, string Value)[]
            {
                ("algorithm", result.Algorithm),
                ("digest", result.Digest),
                ("encoding", result.Encoding),
                ("input format", result.InputFormat),
                ("composition", result.Composition)
            };

            foreach (var (field, value) in fields)
            {
                Assert.False(
                    value.Contains(message, StringComparison.Ordinal),
                    $"The {field} echoed the message back.");
                Assert.False(
                    value.Contains("battery-staple", StringComparison.Ordinal),
                    $"The {field} echoed part of the message back.");
            }

            foreach (var warning in result.Warnings)
            {
                Assert.False(
                    warning.Contains("battery-staple", StringComparison.Ordinal),
                    "An advisory echoed part of the message back.");
            }

            // What the response does say about the input is its size, which gives nothing away that the
            // ciphertext length of an encrypted message would not.
            Assert.Equal(message.Length, result.InputByteCount);
        }

        [Fact]
        public void A_missing_message_is_refused_rather_than_treated_as_an_empty_one()
        {
            // Silently hashing nothing would return a digest the caller would then compare against something
            // else and find matching, which is a worse outcome than an error.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec()));

            Assert.Equal("The message is required.", exception.Message);
        }

        [Fact]
        public void Hashing_without_options_is_rejected_rather_than_silently_defaulted()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.ComputeHash(null!));
        }

        [Theory]
        [InlineData("not base64 at all!")]
        [InlineData("AP8QgH8")]
        [InlineData("====")]
        [InlineData("AP8QgH8=extra")]
        public void A_message_that_is_not_the_format_it_claims_to_be_is_refused(string message)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    InputFormat = HashInputFormat.Base64,
                    Message = message
                }));

            Assert.Contains("not valid Base64", exception.Message, StringComparison.Ordinal);

            // The error names the format that was expected and does not repeat the message, which may be the
            // caller's secret.
            Assert.DoesNotContain(message, exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Hexadecimal_with_an_odd_number_of_digits_is_named_as_such()
        {
            // The mistake that actually happens, usually from a truncated copy, so it is worth telling apart
            // from a bad character.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    InputFormat = HashInputFormat.Hex,
                    Message = "00ff10807"
                }));

            Assert.Contains("odd number of digits", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("00ff10zz")]
        [InlineData("gg")]
        [InlineData("00 ff 10")]
        [InlineData("0x00ff")]
        public void Hexadecimal_with_a_character_that_is_not_a_digit_is_refused(string message)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    InputFormat = HashInputFormat.Hex,
                    Message = message
                }));

            Assert.Contains("not valid hexadecimal", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_algorithm_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    Algorithm = (HashAlgorithmChoice)77,
                    Message = "abc"
                }));

            Assert.Equal("The requested hash algorithm is not supported.", exception.Message);
        }

        [Fact]
        public void An_input_format_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    InputFormat = (HashInputFormat)77,
                    Message = "abc"
                }));

            Assert.Equal("The requested input format is not supported.", exception.Message);
        }

        [Fact]
        public void An_encoding_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    Encoding = (DigestEncoding)77,
                    Message = "abc"
                }));

            Assert.Equal("The requested digest encoding is not supported.", exception.Message);
        }

        [Fact]
        public void A_message_longer_than_the_character_limit_is_refused_before_it_is_decoded()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    Message = new string('a', HashSpec.MaximumInputCharacters + 1)
                }));

            Assert.Contains("characters or fewer", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_message_that_decodes_to_more_bytes_than_the_limit_is_refused()
        {
            // Inside the character limit but over the byte limit once decoded, which is the case the second
            // check exists for: the character count of hexadecimal says nothing directly about the byte count.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.ComputeHash(new HashSpec
                {
                    InputFormat = HashInputFormat.Hex,
                    Message = new string('a', (HashSpec.MaximumInputBytes + 1) * 2)
                }));

            Assert.Contains("bytes or fewer", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_message_at_exactly_the_byte_limit_is_accepted()
        {
            // The boundary is checked from the accepting side too, so the limit cannot quietly drift down by
            // one and refuse something the documentation says is allowed.
            var result = _generator.ComputeHash(new HashSpec
            {
                Message = new string('a', HashSpec.MaximumInputBytes)
            });

            Assert.Equal(HashSpec.MaximumInputBytes, result.InputByteCount);
            Assert.Equal(64, result.Digest.Length);
        }

        [Fact]
        public void The_catalogue_lists_the_supported_functions_strongest_first_with_one_default()
        {
            var catalogue = _generator.HashAlgorithms();

            Assert.Equal(
                new[] { "SHA-512", "SHA-384", "SHA-256", "MD5" },
                catalogue.Select(entry => entry.Algorithm).ToArray());
            Assert.Equal(
                new[] { 512, 384, 256, 128 },
                catalogue.Select(entry => entry.DigestSizeBits).ToArray());

            var defaults = catalogue.Where(entry => entry.IsDefault).ToArray();

            Assert.Single(defaults);
            Assert.Equal("SHA-256", defaults[0].Algorithm);

            // Exactly one broken function is on offer, and it is the last one listed.
            var broken = catalogue.Where(entry => entry.IsCryptographicallyBroken).ToArray();

            Assert.Single(broken);
            Assert.Equal("MD5", broken[0].Algorithm);
            Assert.Equal("MD5", catalogue[^1].Algorithm);

            Assert.All(catalogue, entry => Assert.False(
                string.IsNullOrWhiteSpace(entry.Notes),
                "A catalogue entry had no notes."));
            Assert.All(catalogue, entry => Assert.Equal(entry.Algorithm, entry.Name));
        }

        [Fact]
        public void The_catalogue_does_not_offer_a_password_hashing_function()
        {
            // These belong to a different problem and would invite exactly the confusion the advisories are
            // written to prevent. Their absence is asserted rather than assumed, so adding one has to be a
            // deliberate act that breaks a test.
            var names = _generator.HashAlgorithms().Select(entry => entry.Algorithm).ToArray();

            foreach (var excluded in new[] { "bcrypt", "scrypt", "Argon2", "PBKDF2", "SHA-1" })
            {
                Assert.DoesNotContain(excluded, names, StringComparer.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void The_catalogue_agrees_with_what_the_generator_would_actually_produce()
        {
            // Advertising a name this API would then reject, or a digest size a computed digest does not have,
            // would send a caller down a path that fails later.
            foreach (var entry in _generator.HashAlgorithms())
            {
                var result = _generator.ComputeHash(new HashSpec
                {
                    Algorithm = HashOptions.ParseAlgorithm(entry.Algorithm),
                    Message = "abc"
                });

                Assert.Equal(entry.Algorithm, result.Algorithm);
                Assert.Equal(entry.DigestSizeBits, result.DigestSizeBits);
                Assert.Equal(entry.IsCryptographicallyBroken, result.IsCryptographicallyBroken);
            }
        }

        [Fact]
        public void The_catalogue_is_the_same_list_every_time_it_is_asked_for()
        {
            // Built once and shared, which is only safe because nothing in it varies per caller.
            Assert.Same(_generator.HashAlgorithms(), _generator.HashAlgorithms());
            Assert.Same(_generator.HashAlgorithms(), new HashGenerator().HashAlgorithms());
        }

        [Theory]
        [InlineData("sha256", HashAlgorithmChoice.Sha256)]
        [InlineData("SHA-256", HashAlgorithmChoice.Sha256)]
        [InlineData("SHA_256", HashAlgorithmChoice.Sha256)]
        [InlineData("  sha 256  ", HashAlgorithmChoice.Sha256)]
        [InlineData("md5", HashAlgorithmChoice.Md5)]
        [InlineData("MD-5", HashAlgorithmChoice.Md5)]
        [InlineData("sha512", HashAlgorithmChoice.Sha512)]
        [InlineData(null, HashAlgorithmChoice.Sha256)]
        public void A_function_name_is_read_the_way_a_caller_would_write_it(
            string? supplied,
            HashAlgorithmChoice expected)
        {
            Assert.Equal(expected, HashOptions.ParseAlgorithm(supplied));
        }

        [Theory]
        [InlineData("sha1")]
        [InlineData("sha-1")]
        [InlineData("sha3-256")]
        [InlineData("bcrypt")]
        [InlineData("argon2")]
        [InlineData("pbkdf2")]
        [InlineData("crc32")]
        public void A_function_this_api_does_not_offer_is_refused_rather_than_substituted(string supplied)
        {
            // Quietly computing SHA-256 for a caller who asked for SHA-1 would hand back a digest that fails
            // to match whatever they were comparing against, with nothing in the response to explain why.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => HashOptions.ParseAlgorithm(supplied));

            Assert.Contains("Unsupported hash algorithm", exception.Message, StringComparison.Ordinal);
            Assert.Contains("Sha256", exception.Message, StringComparison.Ordinal);
        }
    }
}
