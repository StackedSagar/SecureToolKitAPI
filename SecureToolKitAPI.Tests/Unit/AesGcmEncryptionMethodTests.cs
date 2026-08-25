using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Encryption;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>Behaviour specific to AES-GCM: key length rules and tamper detection per envelope field.</summary>
    public class AesGcmEncryptionMethodTests
    {
        private static readonly AesGcmEncryptionMethod Method = new();

        /// <summary>Key sizes the AES generator offers, all of which must round trip.</summary>
        public static TheoryData<int> ValidKeySizes => new() { 128, 192, 256 };

        /// <summary>Decoded key lengths in bytes that AES-GCM must reject.</summary>
        public static TheoryData<int> InvalidKeyLengths => new() { 1, 8, 15, 17, 20, 31, 33, 64 };

        [Theory]
        [MemberData(nameof(ValidKeySizes))]
        public void Every_supported_key_size_round_trips(int keySize)
        {
            var key = TestKeys.Aes(keySize);

            var encrypted = Method.Encrypt(key, TestMessages.Unicode);

            Assert.Equal(TestMessages.Unicode, Method.Decrypt(key, encrypted.EncryptedMessage));
        }

        [Theory]
        [MemberData(nameof(InvalidKeyLengths))]
        public void A_key_of_the_wrong_length_is_rejected_before_any_encryption(int keyLengthBytes)
        {
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(keyLengthBytes));

            var encryptFailure = Assert.Throws<CryptographicRequestException>(
                () => Method.Encrypt(key, TestMessages.Normal));
            var decryptFailure = Assert.Throws<CryptographicRequestException>(
                () => Method.Decrypt(key, Method.Encrypt(TestKeys.Aes(), TestMessages.Normal).EncryptedMessage));

            Assert.Contains("16, 24 or 32 bytes", encryptFailure.Message, StringComparison.Ordinal);
            Assert.Contains("16, 24 or 32 bytes", decryptFailure.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_envelope_is_exactly_the_documented_length()
        {
            var key = TestKeys.Aes();

            var encrypted = Method.Encrypt(key, TestMessages.Normal);

            // version(1) + methodId(1) + nonce(12) + tag(16) + ciphertext, which is the plaintext length.
            Assert.Equal(
                2 + 12 + 16 + System.Text.Encoding.UTF8.GetByteCount(TestMessages.Normal),
                EnvelopeEditor.Length(encrypted.EncryptedMessage));
        }

        [Fact]
        public void An_empty_message_produces_an_envelope_with_no_ciphertext_and_still_round_trips()
        {
            var key = TestKeys.Aes();

            var encrypted = Method.Encrypt(key, TestMessages.Empty);

            Assert.Equal(EnvelopeEditor.AesGcmCipherTextIndex, EnvelopeEditor.Length(encrypted.EncryptedMessage));
            Assert.Equal(TestMessages.Empty, Method.Decrypt(key, encrypted.EncryptedMessage));
        }

        [Fact]
        public void The_envelope_header_keeps_the_published_version_and_method_id()
        {
            var envelope = EnvelopeEditor.Decode(Method.Encrypt(TestKeys.Aes(), TestMessages.Normal).EncryptedMessage);

            // These bytes are part of the wire format, so a change here would break existing ciphertexts.
            Assert.Equal((byte)1, envelope[EnvelopeEditor.VersionIndex]);
            Assert.Equal((byte)1, envelope[EnvelopeEditor.MethodIdIndex]);
        }

        [Fact]
        public void The_reported_nonce_and_tag_are_the_ones_embedded_in_the_envelope()
        {
            var encrypted = Method.Encrypt(TestKeys.Aes(), TestMessages.Normal);
            var envelope = EnvelopeEditor.Decode(encrypted.EncryptedMessage);

            Assert.Equal(
                Convert.FromBase64String(encrypted.Parameters.Nonce!),
                envelope[EnvelopeEditor.AesGcmNonceIndex..EnvelopeEditor.AesGcmTagIndex]);
            Assert.Equal(
                Convert.FromBase64String(encrypted.Parameters.AuthenticationTag!),
                envelope[EnvelopeEditor.AesGcmTagIndex..EnvelopeEditor.AesGcmCipherTextIndex]);
            Assert.Null(encrypted.Parameters.EphemeralPublicKey);
        }

        [Theory]
        [InlineData(EnvelopeEditor.AesGcmNonceIndex)]
        [InlineData(EnvelopeEditor.AesGcmTagIndex)]
        [InlineData(EnvelopeEditor.AesGcmCipherTextIndex)]
        public void Altering_any_authenticated_field_is_detected(int index)
        {
            var key = TestKeys.Aes();
            var encrypted = Method.Encrypt(key, TestMessages.Normal);
            var tampered = EnvelopeEditor.FlipByteAt(encrypted.EncryptedMessage, index);

            var exception = Assert.Throws<CryptographicRequestException>(() => Method.Decrypt(key, tampered));

            Assert.Contains("Decryption failed.", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Nonces_are_not_repeated_across_many_encryptions()
        {
            var key = TestKeys.Aes();

            var nonces = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < 200; i++)
            {
                Assert.True(
                    nonces.Add(Method.Encrypt(key, TestMessages.Normal).Parameters.Nonce!),
                    "AES-GCM repeated a nonce for the same key, which would be a serious weakness.");
            }
        }

        [Fact]
        public void A_very_long_message_round_trips_unchanged()
        {
            var key = TestKeys.Aes();

            var encrypted = Method.Encrypt(key, TestMessages.Long);

            Assert.Equal(TestMessages.Long, Method.Decrypt(key, encrypted.EncryptedMessage));
        }
    }
}
