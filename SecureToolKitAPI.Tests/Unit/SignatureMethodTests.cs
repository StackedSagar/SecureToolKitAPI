using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Signing;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// Signing and verification for both signature methods. Signing proves integrity and origin, so
    /// a wrong key or an altered message must produce <c>false</c> rather than a recovered message.
    /// </summary>
    public class SignatureMethodTests
    {
        private static readonly EcdsaSignatureMethod Ecdsa = new();
        private static readonly HmacSha256SignatureMethod Hmac = new();

        /// <summary>Curves the ECDSA generator offers, paired with the P1363 signature length they produce.</summary>
        public static TheoryData<int, int> CurvesAndSignatureLengths => new() { { 256, 64 }, { 384, 96 }, { 521, 132 } };

        /// <summary>Messages both methods must sign and verify.</summary>
        public static TheoryData<string> Messages
        {
            get
            {
                var data = new TheoryData<string>();

                foreach (var message in TestMessages.UniversallySupported())
                {
                    data.Add(message);
                }

                data.Add(TestMessages.Long);
                return data;
            }
        }

        [Theory]
        [MemberData(nameof(Messages))]
        public void Ecdsa_verifies_a_signature_it_produced(string message)
        {
            var keys = TestKeys.Ecdsa();

            var signature = Ecdsa.Sign(keys.PrivateKey(), message);

            Assert.True(Ecdsa.Verify(keys.PublicKey(), message, signature));
        }

        [Theory]
        [MemberData(nameof(Messages))]
        public void Hmac_verifies_a_code_it_produced(string message)
        {
            var secret = TestKeys.HmacSecret();

            var signature = Hmac.Sign(secret, message);

            Assert.True(Hmac.Verify(secret, message, signature));
        }

        [Theory]
        [MemberData(nameof(CurvesAndSignatureLengths))]
        public void Ecdsa_uses_the_curve_matched_digest_and_the_fixed_field_encoding(int keySize, int signatureLength)
        {
            var keys = TestKeys.Ecdsa(keySize);

            var signature = Ecdsa.Sign(keys.PrivateKey(), TestMessages.Normal);

            // IEEE P1363 is r||s, each padded to the curve's field size, which is what Web Crypto expects.
            Assert.Equal(signatureLength, Convert.FromBase64String(signature).Length);
            Assert.True(Ecdsa.Verify(keys.PublicKey(), TestMessages.Normal, signature));
        }

        [Fact]
        public void Hmac_produces_a_32_byte_code()
        {
            var signature = Hmac.Sign(TestKeys.HmacSecret(), TestMessages.Normal);

            Assert.Equal(32, Convert.FromBase64String(signature).Length);
        }

        [Fact]
        public void Hmac_is_deterministic_for_the_same_secret_and_message()
        {
            var secret = TestKeys.HmacSecret();

            var first = Hmac.Sign(secret, TestMessages.Normal);
            var second = Hmac.Sign(secret, TestMessages.Normal);

            // Compared without printing either value, because both are derived from the secret.
            Assert.True(
                string.Equals(first, second, StringComparison.Ordinal),
                "HMAC-SHA256 is deterministic, so signing the same message twice must give the same code.");
        }

        [Fact]
        public void Ecdsa_verifies_every_signature_it_produces_for_the_same_message()
        {
            var keys = TestKeys.Ecdsa();

            var first = Ecdsa.Sign(keys.PrivateKey(), TestMessages.Normal);
            var second = Ecdsa.Sign(keys.PrivateKey(), TestMessages.Normal);

            Assert.True(Ecdsa.Verify(keys.PublicKey(), TestMessages.Normal, first));
            Assert.True(Ecdsa.Verify(keys.PublicKey(), TestMessages.Normal, second));
        }

        [Fact]
        public void A_signature_from_a_different_key_does_not_verify()
        {
            var signer = TestKeys.Ecdsa();
            var other = TestKeys.Ecdsa();
            var secret = TestKeys.HmacSecret();

            var ecdsaSignature = Ecdsa.Sign(signer.PrivateKey(), TestMessages.Normal);
            var hmacSignature = Hmac.Sign(secret, TestMessages.Normal);

            Assert.False(Ecdsa.Verify(other.PublicKey(), TestMessages.Normal, ecdsaSignature));
            Assert.False(Hmac.Verify(TestKeys.HmacSecret(), TestMessages.Normal, hmacSignature));
        }

        [Fact]
        public void An_altered_message_does_not_verify()
        {
            var keys = TestKeys.Ecdsa();
            var secret = TestKeys.HmacSecret();
            var altered = TestMessages.Normal + " ";

            var ecdsaSignature = Ecdsa.Sign(keys.PrivateKey(), TestMessages.Normal);
            var hmacSignature = Hmac.Sign(secret, TestMessages.Normal);

            Assert.False(Ecdsa.Verify(keys.PublicKey(), altered, ecdsaSignature));
            Assert.False(Hmac.Verify(secret, altered, hmacSignature));
        }

        [Fact]
        public void An_altered_signature_does_not_verify()
        {
            var keys = TestKeys.Ecdsa();
            var secret = TestKeys.HmacSecret();

            var ecdsaSignature = EnvelopeEditor.FlipLastByte(Ecdsa.Sign(keys.PrivateKey(), TestMessages.Normal));
            var hmacSignature = EnvelopeEditor.FlipLastByte(Hmac.Sign(secret, TestMessages.Normal));

            Assert.False(Ecdsa.Verify(keys.PublicKey(), TestMessages.Normal, ecdsaSignature));
            Assert.False(Hmac.Verify(secret, TestMessages.Normal, hmacSignature));
        }

        [Fact]
        public void A_signature_of_the_wrong_length_does_not_verify()
        {
            var keys = TestKeys.Ecdsa();
            var secret = TestKeys.HmacSecret();
            var shortSignature = Convert.ToBase64String(RandomNumberGenerator.GetBytes(8));

            Assert.False(Ecdsa.Verify(keys.PublicKey(), TestMessages.Normal, shortSignature));
            Assert.False(Hmac.Verify(secret, TestMessages.Normal, shortSignature));
        }

        [Fact]
        public void Signing_needs_the_private_key_and_verifying_needs_the_public_key()
        {
            var keys = TestKeys.Ecdsa();
            var signature = Ecdsa.Sign(keys.PrivateKey(), TestMessages.Normal);

            var signFailure = Assert.Throws<CryptographicRequestException>(
                () => Ecdsa.Sign(keys.PublicKey(), TestMessages.Normal));
            var verifyFailure = Assert.Throws<CryptographicRequestException>(
                () => Ecdsa.Verify(keys.PrivateKey(), TestMessages.Normal, signature));

            Assert.Contains("private key", signFailure.Message, StringComparison.Ordinal);
            Assert.Contains("public key", verifyFailure.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(8)]
        [InlineData(15)]
        public void An_hmac_secret_below_the_minimum_length_is_refused(int secretLengthBytes)
        {
            var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(secretLengthBytes));

            var signFailure = Assert.Throws<CryptographicRequestException>(() => Hmac.Sign(secret, TestMessages.Normal));
            var verifyFailure = Assert.Throws<CryptographicRequestException>(
                () => Hmac.Verify(secret, TestMessages.Normal, Hmac.Sign(TestKeys.HmacSecret(), TestMessages.Normal)));

            Assert.Contains("at least 16 bytes", signFailure.Message, StringComparison.Ordinal);
            Assert.Contains("at least 16 bytes", verifyFailure.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_hmac_secret_at_the_minimum_length_is_accepted()
        {
            var secret = TestKeys.HmacSecret(128);

            Assert.True(Hmac.Verify(secret, TestMessages.Normal, Hmac.Sign(secret, TestMessages.Normal)));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not base64 !!")]
        public void A_malformed_signature_is_reported_as_a_bad_request_not_a_failed_verification(string signature)
        {
            var keys = TestKeys.Ecdsa();
            var secret = TestKeys.HmacSecret();

            var ecdsaFailure = Assert.Throws<CryptographicRequestException>(
                () => Ecdsa.Verify(keys.PublicKey(), TestMessages.Normal, signature));
            var hmacFailure = Assert.Throws<CryptographicRequestException>(
                () => Hmac.Verify(secret, TestMessages.Normal, signature));

            Assert.Contains("signature", ecdsaFailure.Message, StringComparison.Ordinal);
            Assert.Contains("signature", hmacFailure.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not base64 !!")]
        [InlineData("AAAA")]
        public void A_malformed_key_is_refused(string key)
        {
            Assert.Throws<CryptographicRequestException>(() => Ecdsa.Sign(key, TestMessages.Normal));
            Assert.Throws<CryptographicRequestException>(() => Hmac.Sign(key, TestMessages.Normal));
        }

        [Fact]
        public void Each_method_describes_itself_for_the_api_documentation()
        {
            foreach (ISignatureMethod method in new ISignatureMethod[] { Ecdsa, Hmac })
            {
                Assert.False(string.IsNullOrWhiteSpace(method.Name));
                Assert.NotEmpty(method.Aliases);
                Assert.False(string.IsNullOrWhiteSpace(method.Description));
                Assert.False(string.IsNullOrWhiteSpace(method.SigningKeyFormat));
                Assert.False(string.IsNullOrWhiteSpace(method.VerificationKeyFormat));
                Assert.False(string.IsNullOrWhiteSpace(method.SignatureFormat));
            }
        }
    }
}
