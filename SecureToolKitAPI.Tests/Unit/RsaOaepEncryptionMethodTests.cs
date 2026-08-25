using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Encryption;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Behaviour specific to RSA-OAEP: the key-size floor, the message-size ceiling, and the
    /// public/private key roles.
    /// </summary>
    public class RsaOaepEncryptionMethodTests
    {
        private static readonly RsaOaepEncryptionMethod Method = new();

        // RSA generation is slow, so one throwaway pair is shared by the tests that only need a valid key.
        private static readonly Lazy<GeneratedKey> SharedKeyPair = new(() => TestKeys.Rsa());

        /// <summary>Key sizes the encryption endpoints must refuse as too weak.</summary>
        public static TheoryData<int> TooSmallKeySizes => new() { 512, 1024 };

        [Theory]
        [InlineData(2048, 190)]
        [InlineData(3072, 318)]
        [InlineData(4096, 446)]
        public void The_message_limit_matches_the_oaep_sha256_formula(int keySizeBits, int expectedMaxBytes)
        {
            // keySize/8 - 2 * hashLength - 2, with SHA-256 producing a 32 byte hash.
            Assert.Equal(expectedMaxBytes, RsaOaepEncryptionMethod.MaxMessageLength(keySizeBits));
        }

        [Fact]
        public void A_message_at_the_limit_round_trips()
        {
            var keys = SharedKeyPair.Value;

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.RsaMaximumFor2048);

            Assert.Equal(TestMessages.RsaMaximumFor2048, Method.Decrypt(keys.PrivateKey(), encrypted.EncryptedMessage));
        }

        [Fact]
        public void A_message_one_byte_over_the_limit_is_refused_with_actionable_guidance()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => Method.Encrypt(SharedKeyPair.Value.PublicKey(), TestMessages.RsaOversizedFor2048));

            Assert.Contains("too large", exception.Message, StringComparison.Ordinal);
            Assert.Contains("190 bytes", exception.Message, StringComparison.Ordinal);
            Assert.Contains("ecc-hillman", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_long_message_is_refused_rather_than_silently_truncated()
        {
            Assert.Throws<CryptographicRequestException>(
                () => Method.Encrypt(SharedKeyPair.Value.PublicKey(), TestMessages.Long));
        }

        [Theory]
        [MemberData(nameof(TooSmallKeySizes))]
        public void Keys_below_the_minimum_size_are_refused_for_both_directions(int keySizeBits)
        {
            var weak = TestKeys.Rsa(keySizeBits);
            var strong = SharedKeyPair.Value;
            var envelope = Method.Encrypt(strong.PublicKey(), TestMessages.Normal).EncryptedMessage;

            var encryptFailure = Assert.Throws<CryptographicRequestException>(
                () => Method.Encrypt(weak.PublicKey(), TestMessages.Normal));
            var decryptFailure = Assert.Throws<CryptographicRequestException>(
                () => Method.Decrypt(weak.PrivateKey(), envelope));

            Assert.Contains("smaller than 2048 bits", encryptFailure.Message, StringComparison.Ordinal);
            Assert.Contains("smaller than 2048 bits", decryptFailure.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Decrypting_with_the_public_key_is_refused()
        {
            var keys = SharedKeyPair.Value;
            var envelope = Method.Encrypt(keys.PublicKey(), TestMessages.Normal).EncryptedMessage;

            var exception = Assert.Throws<CryptographicRequestException>(
                () => Method.Decrypt(keys.PublicKey(), envelope));

            Assert.Contains("not a valid RSA private key", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_x509_and_pkcs8_key_encodings_are_also_accepted()
        {
            var keys = SharedKeyPair.Value;

            using var source = RSA.Create();
            source.ImportRSAPrivateKey(Convert.FromBase64String(keys.PrivateKey()), out _);

            var subjectPublicKeyInfo = Convert.ToBase64String(source.ExportSubjectPublicKeyInfo());
            var pkcs8PrivateKey = Convert.ToBase64String(source.ExportPkcs8PrivateKey());

            var encrypted = Method.Encrypt(subjectPublicKeyInfo, TestMessages.Normal);

            Assert.Equal(TestMessages.Normal, Method.Decrypt(pkcs8PrivateKey, encrypted.EncryptedMessage));
        }

        [Fact]
        public void The_envelope_is_the_documented_size_and_carries_the_published_header()
        {
            var keys = SharedKeyPair.Value;

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Normal);
            var envelope = EnvelopeEditor.Decode(encrypted.EncryptedMessage);

            // version(1) + methodId(1) + ciphertext(keySize/8).
            Assert.Equal(2 + (keys.KeySizeBits / 8), envelope.Length);
            Assert.Equal((byte)1, envelope[EnvelopeEditor.VersionIndex]);
            Assert.Equal((byte)2, envelope[EnvelopeEditor.MethodIdIndex]);
        }

        [Fact]
        public void No_nonce_tag_or_ephemeral_key_is_reported_because_the_method_uses_none()
        {
            var encrypted = Method.Encrypt(SharedKeyPair.Value.PublicKey(), TestMessages.Normal);

            Assert.Null(encrypted.Parameters.Nonce);
            Assert.Null(encrypted.Parameters.AuthenticationTag);
            Assert.Null(encrypted.Parameters.EphemeralPublicKey);
        }

        [Fact]
        public void An_empty_message_round_trips()
        {
            var keys = SharedKeyPair.Value;

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Empty);

            Assert.Equal(TestMessages.Empty, Method.Decrypt(keys.PrivateKey(), encrypted.EncryptedMessage));
        }

        [Fact]
        public void An_elliptic_curve_key_is_not_accepted_as_an_rsa_key()
        {
            var ecc = TestKeys.Ecdh();

            Assert.Throws<CryptographicRequestException>(() => Method.Encrypt(ecc.PublicKey(), TestMessages.Normal));
        }
    }
}
