using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Salts;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The salt generator: that it produces the requested number of bytes in the requested encoding,
    /// describes what it produced accurately, refuses options it cannot satisfy, and never returns the
    /// same salt twice.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A salt is not secret, so printing one in a failure message would leak nothing. The assertions still
    /// avoid it, because the same test file would otherwise teach the wrong habit for the generators whose
    /// output is secret, and because a length or a boolean says more about a defect than the value does.
    /// </para>
    /// <para>
    /// Randomness cannot be seeded — the generator draws from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>, which is the point — so
    /// uniqueness is checked by repeating a generation and asserting a property that must hold every time.
    /// </para>
    /// </remarks>
    public class SaltGeneratorTests
    {
        /// <summary>
        /// How many salts the uniqueness check draws. Enough that a generator reusing a value would fail
        /// reliably, small enough to keep the suite fast.
        /// </summary>
        private const int Iterations = 50;

        private readonly SaltGenerator _generator = new();

        [Fact]
        public void The_default_salt_is_16_bytes_encoded_as_base64()
        {
            var result = _generator.Generate(new SaltSpec());

            Assert.Equal(16, result.Bytes);

            // 16 bytes is 24 Base64 characters, the last two of which are padding.
            Assert.Equal(24, result.Value.Length);
            Assert.Equal("Base64 encoded, 16 random bytes.", result.Format);
        }

        [Theory]
        [InlineData(SecretEncoding.Base64, 16, 24)]
        [InlineData(SecretEncoding.Base64, 32, 44)]
        [InlineData(SecretEncoding.Base64Url, 16, 22)]
        [InlineData(SecretEncoding.Base64Url, 32, 43)]
        [InlineData(SecretEncoding.Hex, 16, 32)]
        [InlineData(SecretEncoding.Hex, 32, 64)]
        [InlineData(SecretEncoding.HexUpper, 8, 16)]
        [InlineData(SecretEncoding.HexUpper, 64, 128)]
        public void A_salt_has_the_length_its_encoding_implies(
            SecretEncoding encoding,
            int bytes,
            int expectedLength)
        {
            var result = _generator.Generate(new SaltSpec { Bytes = bytes, Encoding = encoding });

            Assert.Equal(bytes, result.Bytes);
            Assert.Equal(expectedLength, result.Value.Length);
        }

        [Theory]
        [InlineData(SecretEncoding.Base64, "Base64 encoded, 24 random bytes.")]
        [InlineData(SecretEncoding.Base64Url, "Base64url encoded, 24 random bytes.")]
        [InlineData(SecretEncoding.Hex, "hexadecimal, 24 random bytes.")]
        [InlineData(SecretEncoding.HexUpper, "uppercase hexadecimal, 24 random bytes.")]
        public void The_format_names_the_encoding_and_the_size_so_a_caller_knows_what_to_decode(
            SecretEncoding encoding,
            string expectedFormat)
        {
            var result = _generator.Generate(new SaltSpec { Bytes = 24, Encoding = encoding });

            Assert.Equal(expectedFormat, result.Format);
        }

        [Fact]
        public void A_hex_salt_uses_the_case_it_was_asked_for()
        {
            var lower = _generator.Generate(new SaltSpec { Encoding = SecretEncoding.Hex });
            var upper = _generator.Generate(new SaltSpec { Encoding = SecretEncoding.HexUpper });

            Assert.True(
                lower.Value.All(character => !char.IsAsciiLetterUpper(character)),
                "A lowercase hexadecimal salt contained an uppercase character.");
            Assert.True(
                upper.Value.All(character => !char.IsAsciiLetterLower(character)),
                "An uppercase hexadecimal salt contained a lowercase character.");
        }

        [Fact]
        public void Every_salt_is_drawn_independently_which_is_the_only_thing_a_salt_is_for()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);

            for (var iteration = 0; iteration < Iterations; iteration++)
            {
                seen.Add(_generator.Generate(new SaltSpec()).Value);
            }

            Assert.Equal(Iterations, seen.Count);
        }

        [Fact]
        public void The_advisories_say_that_a_salt_must_be_stored_never_reused_and_is_not_a_hash_function()
        {
            var result = _generator.Generate(new SaltSpec());

            Assert.Equal(3, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("must be stored with the", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("new salt for every value hashed", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("not a substitute for a password-hashing function", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(7)]
        [InlineData(65)]
        [InlineData(int.MaxValue)]
        public void A_size_outside_the_supported_range_is_refused_before_any_randomness_is_drawn(int bytes)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.Generate(new SaltSpec { Bytes = bytes }));

            Assert.Contains("between 8 and 64 bytes", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_boundaries_of_the_supported_range_are_accepted()
        {
            Assert.Equal(
                SaltSpec.MinimumBytes,
                _generator.Generate(new SaltSpec { Bytes = SaltSpec.MinimumBytes }).Bytes);
            Assert.Equal(
                SaltSpec.MaximumBytes,
                _generator.Generate(new SaltSpec { Bytes = SaltSpec.MaximumBytes }).Bytes);
        }

        [Fact]
        public void Base62_is_refused_because_it_cannot_be_decoded_back_to_the_bytes_that_were_generated()
        {
            // Sampled characters carry no recoverable byte sequence, so a Base62 salt could not be used to
            // verify the hash it was generated for. Refused rather than quietly replaced with another
            // encoding, which would hand the caller a value it did not ask for.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.Generate(new SaltSpec { Encoding = SecretEncoding.Base62 }));

            Assert.Contains("not a byte encoding", exception.Message, StringComparison.Ordinal);
            Assert.Contains("Base64, Base64Url, Hex, HexUpper", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_encoding_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.Generate(new SaltSpec { Encoding = (SecretEncoding)987 }));

            Assert.Contains("not supported", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Generating_without_options_is_rejected_rather_than_silently_defaulted()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.Generate(null!));
        }
    }
}
