using System.Text;
using SecureToolKitAPI.Cryptography.Internal;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Base32 conversion: that it produces exactly what RFC 4648 says it should, that anything encoded
    /// here decodes back to the bytes it came from, that the presentation a person adds to a secret is
    /// tolerated, and that malformed input is refused rather than silently truncated.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is an encoding, not a cipher, so the vectors are public and printing them is safe. That is
    /// exactly why the vectors matter: nothing about a wrong Base32 result looks wrong, it simply produces
    /// a TOTP secret that no authenticator agrees with, so the published vectors from RFC 4648 §10 are
    /// asserted character for character.
    /// </para>
    /// <para>
    /// The expected outputs are written out as literals rather than computed, so an error in the
    /// implementation cannot travel through the test.
    /// </para>
    /// </remarks>
    public class Base32TextTests
    {
        /// <summary>How many random inputs the round-trip properties are checked over.</summary>
        private const int Iterations = 200;

        /// <summary>
        /// The RFC 4648 §10 test vectors, which are the reference every Base32 implementation is measured
        /// against.
        /// </summary>
        public static TheoryData<string, string> Rfc4648Vectors => new()
        {
            { string.Empty, string.Empty },
            { "f", "MY======" },
            { "fo", "MZXQ====" },
            { "foo", "MZXW6===" },
            { "foob", "MZXW6YQ=" },
            { "fooba", "MZXW6YTB" },
            { "foobar", "MZXW6YTBOI======" }
        };

        /// <summary>Symbol counts that no whole number of bytes can encode to.</summary>
        public static TheoryData<string> ImpossibleLengths => new()
        {
            "A",
            "AAA",
            "AAAAAA",
            "MZXW6YTBOIA"
        };

        [Theory]
        [MemberData(nameof(Rfc4648Vectors))]
        public void Encoding_matches_the_published_vectors(string plain, string expected)
        {
            Assert.Equal(expected, Base32Text.Encode(Encoding.ASCII.GetBytes(plain)));
        }

        [Theory]
        [MemberData(nameof(Rfc4648Vectors))]
        public void Encoding_without_padding_is_the_published_vector_without_its_padding(
            string plain,
            string expected)
        {
            Assert.Equal(
                expected.TrimEnd('='),
                Base32Text.Encode(Encoding.ASCII.GetBytes(plain), padding: false));
        }

        [Theory]
        [MemberData(nameof(Rfc4648Vectors))]
        public void Decoding_a_published_vector_returns_the_bytes_it_encodes(string plain, string encoded)
        {
            Assert.True(Base32Text.TryDecode(encoded, out var decoded), "A published vector was rejected.");
            Assert.Equal(Encoding.ASCII.GetBytes(plain), decoded);
        }

        [Theory]
        [MemberData(nameof(Rfc4648Vectors))]
        public void Padding_is_optional_when_decoding(string plain, string encoded)
        {
            Assert.True(
                Base32Text.TryDecode(encoded.TrimEnd('='), out var decoded),
                "An unpadded value was rejected, but padding carries no information.");

            Assert.Equal(Encoding.ASCII.GetBytes(plain), decoded);
        }

        [Fact]
        public void An_empty_input_encodes_to_an_empty_string()
        {
            Assert.Equal(string.Empty, Base32Text.Encode(ReadOnlySpan<byte>.Empty));
            Assert.Equal(string.Empty, Base32Text.Encode(ReadOnlySpan<byte>.Empty, padding: false));
        }

        [Fact]
        public void A_padded_value_is_always_a_whole_number_of_blocks()
        {
            for (var length = 1; length <= 40; length++)
            {
                var encoded = Base32Text.Encode(new byte[length]);

                Assert.True(
                    encoded.Length % 8 == 0,
                    $"Encoding {length} bytes produced {encoded.Length} characters, which is not a whole "
                    + "number of eight-character blocks.");
            }
        }

        [Fact]
        public void Anything_encoded_decodes_back_to_the_same_bytes()
        {
            // Deterministic, so a failure can be reproduced from the seed rather than only sometimes.
            var random = new Random(20260824);

            for (var iteration = 0; iteration < Iterations; iteration++)
            {
                var value = new byte[random.Next(0, 65)];
                random.NextBytes(value);

                Assert.True(
                    Base32Text.TryDecode(Base32Text.Encode(value), out var fromPadded),
                    "A value this encoder produced was rejected by its own decoder.");

                Assert.Equal(value, fromPadded);

                Assert.True(
                    Base32Text.TryDecode(Base32Text.Encode(value, padding: false), out var fromUnpadded),
                    "An unpadded value this encoder produced was rejected by its own decoder.");

                Assert.Equal(value, fromUnpadded);
            }
        }

        [Fact]
        public void Every_byte_value_survives_a_round_trip()
        {
            // The high bytes are where a sign-extension or masking error would show, and a 256-byte input
            // crosses many block boundaries.
            var value = new byte[256];

            for (var index = 0; index < value.Length; index++)
            {
                value[index] = (byte)index;
            }

            Assert.True(Base32Text.TryDecode(Base32Text.Encode(value), out var decoded), "Round trip failed.");
            Assert.Equal(value, decoded);
        }

        [Fact]
        public void The_encoding_uses_only_the_rfc_alphabet_and_padding()
        {
            var value = new byte[64];
            new Random(4648).NextBytes(value);

            Assert.All(
                Base32Text.Encode(value),
                character => Assert.True(
                    character == '='
                    || "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".Contains(character, StringComparison.Ordinal),
                    $"The encoding contained '{character}', which is not in the RFC 4648 alphabet."));
        }

        [Fact]
        public void Lowercase_input_decodes_the_same_as_uppercase()
        {
            Assert.True(Base32Text.TryDecode("mzxw6ytboi======", out var decoded), "Lowercase was rejected.");
            Assert.Equal("foobar"u8.ToArray(), decoded);
        }

        [Fact]
        public void The_grouping_and_whitespace_people_add_to_a_secret_are_ignored()
        {
            // How a secret looks when it has been printed for a person to read back, or pasted with the
            // line break that came with it.
            Assert.True(
                Base32Text.TryDecode(" mzxw-6ytb-oi\n", out var decoded),
                "A grouped, lowercase value with surrounding whitespace was rejected.");

            Assert.Equal("foobar"u8.ToArray(), decoded);
        }

        [Theory]
        [MemberData(nameof(ImpossibleLengths))]
        public void A_symbol_count_no_input_can_produce_is_rejected(string encoded)
        {
            Assert.False(
                Base32Text.TryDecode(encoded, out var decoded),
                $"'{encoded}' was accepted, but no whole number of bytes encodes to that many symbols.");

            Assert.Empty(decoded);
        }

        [Theory]
        [InlineData("M1XW6YTB")]
        [InlineData("M8XW6YTB")]
        [InlineData("M0XW6YTB")]
        [InlineData("MZXW6YT!")]
        [InlineData("MZXW6YT ?")]
        public void A_character_outside_the_alphabet_is_rejected(string encoded)
        {
            Assert.False(
                Base32Text.TryDecode(encoded, out var decoded),
                $"'{encoded}' was accepted, but it contains a character the alphabet does not include.");

            Assert.Empty(decoded);
        }

        [Fact]
        public void A_symbol_after_the_padding_begins_is_rejected()
        {
            // Two values concatenated, or a corrupted one. Reading past the padding would quietly return
            // bytes no encoder ever produced.
            Assert.False(
                Base32Text.TryDecode("MZXW6===YTB", out var decoded),
                "A value with data after its padding was accepted.");

            Assert.Empty(decoded);
        }

        [Fact]
        public void Null_is_rejected_rather_than_treated_as_empty()
        {
            Assert.False(Base32Text.TryDecode(null, out var decoded), "Null was accepted as valid Base32.");
            Assert.Empty(decoded);
        }

        [Fact]
        public void Text_that_is_only_presentation_decodes_to_nothing()
        {
            // Zero symbols is a legal count, so this is empty rather than invalid — the caller decides
            // whether an empty secret is acceptable, which it separately refuses.
            Assert.True(Base32Text.TryDecode("  --  ", out var decoded), "An input with no symbols was rejected.");
            Assert.Empty(decoded);
        }

        [Fact]
        public void Leftover_bits_in_a_final_block_are_discarded_rather_than_refused()
        {
            // MZXQ and MZXR differ only in bits that fall outside the two encoded bytes. Several
            // authenticators emit a value like the second one, and refusing a secret every other tool
            // accepts would be the worse failure.
            Assert.True(Base32Text.TryDecode("MZXR", out var decoded), "A value with non-zero leftover bits was rejected.");
            Assert.Equal("fo"u8.ToArray(), decoded);
        }
    }
}
