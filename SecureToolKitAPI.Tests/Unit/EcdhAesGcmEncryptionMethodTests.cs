using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Encryption;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Behaviour specific to the hybrid ECDH + AES-GCM method: the ephemeral key carried in the
    /// envelope, the curve match between the two sides, and the key roles.
    /// </summary>
    public class EcdhAesGcmEncryptionMethodTests
    {
        private const int EphemeralKeyLengthPrefix = 2;
        private const int EphemeralKeyIndex = EnvelopeEditor.PayloadIndex + EphemeralKeyLengthPrefix;

        private static readonly EcdhAesGcmEncryptionMethod Method = new();

        /// <summary>Curves the ECDH generator offers, all of which must round trip.</summary>
        public static TheoryData<int> SupportedCurves => new() { 256, 384, 521 };

        [Theory]
        [MemberData(nameof(SupportedCurves))]
        public void Every_supported_curve_round_trips(int keySize)
        {
            var keys = TestKeys.Ecdh(keySize);

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Unicode);

            Assert.Equal(TestMessages.Unicode, Method.Decrypt(keys.PrivateKey(), encrypted.EncryptedMessage));
        }

        [Fact]
        public void A_message_far_larger_than_any_key_round_trips_because_the_method_is_hybrid()
        {
            var keys = TestKeys.Ecdh();

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Long);

            Assert.Equal(TestMessages.Long, Method.Decrypt(keys.PrivateKey(), encrypted.EncryptedMessage));
        }

        [Fact]
        public void The_envelope_carries_the_reported_ephemeral_public_key()
        {
            var keys = TestKeys.Ecdh();

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Normal);
            var envelope = EnvelopeEditor.Decode(encrypted.EncryptedMessage);
            var reportedEphemeralKey = Convert.FromBase64String(encrypted.Parameters.EphemeralPublicKey!);

            var declaredLength = (envelope[EnvelopeEditor.PayloadIndex] << 8)
                | envelope[EnvelopeEditor.PayloadIndex + 1];

            Assert.Equal(reportedEphemeralKey.Length, declaredLength);
            Assert.Equal(
                reportedEphemeralKey,
                envelope[EphemeralKeyIndex..(EphemeralKeyIndex + declaredLength)]);
            Assert.Equal(
                EphemeralKeyIndex + declaredLength + 12 + 16 + System.Text.Encoding.UTF8.GetByteCount(TestMessages.Normal),
                envelope.Length);
        }

        [Fact]
        public void The_envelope_header_keeps_the_published_version_and_method_id()
        {
            var envelope = EnvelopeEditor.Decode(
                Method.Encrypt(TestKeys.Ecdh().PublicKey(), TestMessages.Normal).EncryptedMessage);

            Assert.Equal((byte)1, envelope[EnvelopeEditor.VersionIndex]);
            Assert.Equal((byte)3, envelope[EnvelopeEditor.MethodIdIndex]);
        }

        [Fact]
        public void A_new_ephemeral_key_is_used_for_every_message()
        {
            var recipient = TestKeys.Ecdh().PublicKey();

            var first = Method.Encrypt(recipient, TestMessages.Normal);
            var second = Method.Encrypt(recipient, TestMessages.Normal);

            Assert.False(
                string.Equals(
                    first.Parameters.EphemeralPublicKey,
                    second.Parameters.EphemeralPublicKey,
                    StringComparison.Ordinal),
                "The ephemeral key was reused, so the derived AES key would be reused too.");
        }

        [Fact]
        public void Replacing_the_ephemeral_key_with_another_valid_key_is_detected()
        {
            var keys = TestKeys.Ecdh();
            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Normal);

            // Another key on the same curve has an identical encoded length, so the envelope stays
            // structurally valid and only the authenticated key agreement can catch the substitution.
            var substitute = Convert.FromBase64String(TestKeys.Ecdh().PublicKey());
            var tampered = EnvelopeEditor.Replace(encrypted.EncryptedMessage, EphemeralKeyIndex, substitute);

            Assert.Throws<CryptographicRequestException>(() => Method.Decrypt(keys.PrivateKey(), tampered));
        }

        [Theory]
        [InlineData(0, 0)]
        [InlineData(255, 255)]
        public void A_dishonest_ephemeral_key_length_is_rejected_as_malformed(byte high, byte low)
        {
            var keys = TestKeys.Ecdh();
            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Normal);
            var tampered = EnvelopeEditor.Replace(
                encrypted.EncryptedMessage,
                EnvelopeEditor.PayloadIndex,
                new[] { high, low });

            var exception = Assert.Throws<CryptographicRequestException>(
                () => Method.Decrypt(keys.PrivateKey(), tampered));

            Assert.Contains("malformed", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_key_on_a_different_curve_cannot_complete_the_key_agreement()
        {
            var encrypted = Method.Encrypt(TestKeys.Ecdh(256).PublicKey(), TestMessages.Normal);

            var exception = Assert.Throws<CryptographicRequestException>(
                () => Method.Decrypt(TestKeys.Ecdh(384).PrivateKey(), encrypted.EncryptedMessage));

            Assert.Contains("does not match the curve", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Encrypting_needs_the_public_key_and_decrypting_needs_the_private_key()
        {
            var keys = TestKeys.Ecdh();
            var envelope = Method.Encrypt(keys.PublicKey(), TestMessages.Normal).EncryptedMessage;

            var encryptFailure = Assert.Throws<CryptographicRequestException>(
                () => Method.Encrypt(keys.PrivateKey(), TestMessages.Normal));
            var decryptFailure = Assert.Throws<CryptographicRequestException>(
                () => Method.Decrypt(keys.PublicKey(), envelope));

            Assert.Contains("public key", encryptFailure.Message, StringComparison.Ordinal);
            Assert.Contains("private key", decryptFailure.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_rsa_key_is_not_accepted_as_an_elliptic_curve_key()
        {
            var rsa = TestKeys.Rsa();

            Assert.Throws<CryptographicRequestException>(() => Method.Encrypt(rsa.PublicKey(), TestMessages.Normal));
        }

        [Fact]
        public void An_empty_message_round_trips()
        {
            var keys = TestKeys.Ecdh();

            var encrypted = Method.Encrypt(keys.PublicKey(), TestMessages.Empty);

            Assert.Equal(TestMessages.Empty, Method.Decrypt(keys.PrivateKey(), encrypted.EncryptedMessage));
        }
    }
}
