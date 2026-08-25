using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Tests.TestSupport;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The behaviour every encryption method must share: a faithful round trip, and a safe refusal for
    /// wrong keys, malformed envelopes and tampered ciphertext.
    /// </summary>
    public class EncryptionMethodContractTests
    {
        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethodsAndMessages), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_an_encrypted_message_returns_the_original(string methodName, string message)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, message);
            var decrypted = scenario.Method.Decrypt(scenario.DecryptionKey, encrypted.EncryptedMessage);

            Assert.Equal(message, decrypted);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_the_largest_supported_message_returns_the_original(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, scenario.LargestMessage);
            var decrypted = scenario.Method.Decrypt(scenario.DecryptionKey, encrypted.EncryptedMessage);

            Assert.Equal(scenario.LargestMessage, decrypted);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Encrypting_the_same_message_twice_produces_different_envelopes(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            var first = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);
            var second = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);

            Assert.False(
                string.Equals(first.EncryptedMessage, second.EncryptedMessage, StringComparison.Ordinal),
                $"'{methodName}' produced an identical envelope twice, so the per-message randomness is not being applied.");
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_with_a_different_key_of_the_same_kind_is_refused(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);

            Assert.Throws<CryptographicRequestException>(
                () => scenario.Method.Decrypt(scenario.WrongDecryptionKey, encrypted.EncryptedMessage));
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_a_corrupted_envelope_is_refused(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);
            var corrupted = EnvelopeEditor.FlipLastByte(encrypted.EncryptedMessage);

            Assert.Throws<CryptographicRequestException>(
                () => scenario.Method.Decrypt(scenario.DecryptionKey, corrupted));
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_a_truncated_envelope_is_refused(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);
            var length = EnvelopeEditor.Length(encrypted.EncryptedMessage);

            foreach (var truncatedLength in new[] { 0, 1, 2, 3, length / 2, length - 1 })
            {
                var truncated = EnvelopeEditor.Truncate(encrypted.EncryptedMessage, truncatedLength);

                Assert.Throws<CryptographicRequestException>(
                    () => scenario.Method.Decrypt(scenario.DecryptionKey, truncated));
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_an_envelope_from_another_method_reports_the_mismatch(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);

            // 0x7F is not a method identifier this API issues.
            var relabelled = EnvelopeEditor.WithMethodId(encrypted.EncryptedMessage, 0x7F);

            var exception = Assert.Throws<CryptographicRequestException>(
                () => scenario.Method.Decrypt(scenario.DecryptionKey, relabelled));

            Assert.Contains("different encryption method", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_an_envelope_with_an_unknown_version_reports_the_version(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);
            var futureVersion = EnvelopeEditor.WithVersion(encrypted.EncryptedMessage, 0x42);

            var exception = Assert.Throws<CryptographicRequestException>(
                () => scenario.Method.Decrypt(scenario.DecryptionKey, futureVersion));

            Assert.Contains("format version", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Encrypting_with_a_malformed_key_is_refused(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            foreach (var key in new[] { "", "   ", "not base64 !!", "AAAA" })
            {
                Assert.Throws<CryptographicRequestException>(
                    () => scenario.Method.Encrypt(key, TestMessages.Normal));
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_with_a_malformed_key_is_refused(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);

            foreach (var key in new[] { "", "   ", "not base64 !!", "AAAA" })
            {
                Assert.Throws<CryptographicRequestException>(
                    () => scenario.Method.Decrypt(key, encrypted.EncryptedMessage));
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Decrypting_a_malformed_envelope_is_refused(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            foreach (var envelope in new[] { "", "   ", "not base64 !!" })
            {
                Assert.Throws<CryptographicRequestException>(
                    () => scenario.Method.Decrypt(scenario.DecryptionKey, envelope));
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Errors_never_echo_the_supplied_key_or_message(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);
            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);
            var corrupted = EnvelopeEditor.FlipLastByte(encrypted.EncryptedMessage);

            var exception = Assert.Throws<CryptographicRequestException>(
                () => scenario.Method.Decrypt(scenario.DecryptionKey, corrupted));

            Assert.False(
                exception.Message.Contains(scenario.DecryptionKey, StringComparison.Ordinal),
                "The error message echoed the supplied key.");
            Assert.False(
                exception.Message.Contains(corrupted, StringComparison.Ordinal),
                "The error message echoed the supplied ciphertext.");
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AllMethods), MemberType = typeof(EncryptionScenarios))]
        public void Method_describes_itself_for_the_api_documentation(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            Assert.Equal(methodName, scenario.Method.Name);
            Assert.NotEmpty(scenario.Method.Aliases);
            Assert.False(string.IsNullOrWhiteSpace(scenario.Method.Description));
            Assert.False(string.IsNullOrWhiteSpace(scenario.Method.KeyFormat));
            Assert.Contains("version(1)", scenario.Method.EnvelopeLayout, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AuthenticatedMethods), MemberType = typeof(EncryptionScenarios))]
        public void Authenticated_methods_report_their_nonce_and_tag(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            var encrypted = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);

            Assert.NotNull(encrypted.Parameters.Nonce);
            Assert.NotNull(encrypted.Parameters.AuthenticationTag);
            Assert.Equal(12, Convert.FromBase64String(encrypted.Parameters.Nonce!).Length);
            Assert.Equal(16, Convert.FromBase64String(encrypted.Parameters.AuthenticationTag!).Length);
        }

        [Theory]
        [MemberData(nameof(EncryptionScenarios.AuthenticatedMethods), MemberType = typeof(EncryptionScenarios))]
        public void Authenticated_methods_use_a_fresh_nonce_for_every_message(string methodName)
        {
            var scenario = EncryptionScenarios.Create(methodName);

            var first = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);
            var second = scenario.Method.Encrypt(scenario.EncryptionKey, TestMessages.Normal);

            Assert.False(
                string.Equals(first.Parameters.Nonce, second.Parameters.Nonce, StringComparison.Ordinal),
                $"'{methodName}' reused a nonce, which would break the security of AES-GCM.");
        }
    }
}
