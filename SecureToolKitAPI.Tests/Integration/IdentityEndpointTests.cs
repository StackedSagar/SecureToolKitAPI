using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The identity endpoints over HTTP: that every route answers, that the options in the body are applied,
    /// that the TOTP codes match the vectors published in RFC 6238 when they come back through the API, that
    /// a supplied secret is never echoed, and that unusable options become a problem response rather than an
    /// exception.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A generated secret is never asserted against a fixed expectation and never printed: those assertions
    /// check size, alphabet and uniqueness through booleans carrying a message instead. The secrets that do
    /// appear as literals here are the seeds published in RFC 6238 Appendix B — test vectors from a
    /// standards document rather than credentials, and useless anywhere real.
    /// </para>
    /// <para>
    /// The five generating routes are POST with the values in the body, which is what keeps a TOTP secret out
    /// of server logs, proxy logs and browser history; the wrong-verb test exists to keep it that way. The
    /// card listing is a GET because it generates nothing and returns only published data.
    /// </para>
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class IdentityEndpointTests(ApiFactory factory)
    {
        /// <summary>The routes that answer with their documented defaults when no body is sent.</summary>
        public static TheoryData<string> DefaultedRoutes => new()
        {
            "/api/identity/uuid",
            "/api/identity/totp-secret"
        };

        /// <summary>Every route that must refuse a GET, because a GET would put a secret in a URL.</summary>
        public static TheoryData<string> PostOnlyRoutes => new()
        {
            "/api/identity/uuid",
            "/api/identity/totp-secret",
            "/api/identity/totp-authenticator",
            "/api/identity/totp-code",
            "/api/identity/base32"
        };

        /// <summary>The RFC 4648 Base32 alphabet, written out so a change to the encoder fails here.</summary>
        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <summary>
        /// The RFC 6238 SHA-1 seed, Base32 encoded. A published test vector, not a credential.
        /// </summary>
        private const string Sha1Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        /// <summary>The RFC 6238 SHA-512 seed, Base32 encoded. A published test vector, not a credential.</summary>
        private const string Sha512Seed =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

        private readonly HttpClient _client = factory.CreateClient();

        [Theory]
        [MemberData(nameof(DefaultedRoutes))]
        public async Task Each_defaulted_route_answers_without_a_body(string route)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.False(
                string.IsNullOrWhiteSpace(body.RequiredString("composition")),
                "The composition was missing.");
            Assert.NotEmpty(body.GetProperty("warnings").EnumerateArray());
        }

        [Fact]
        public async Task The_uuid_route_returns_one_hyphenated_version_four_value_by_default()
        {
            var response = await _client.PostAsync("/api/identity/uuid", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(1, body.GetProperty("count").GetInt32());
            Assert.Equal("v4", body.RequiredString("version"));
            Assert.Equal("hyphenated", body.RequiredString("format"));
            Assert.Equal(122, body.GetProperty("randomBits").GetInt32());

            var values = Values(body);

            Assert.Single(values);
            Assert.Equal(36, values[0].Length);
            Assert.Equal('4', values[0][14]);
        }

        [Fact]
        public async Task The_requested_uuid_options_are_applied()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/uuid",
                new { count = 5, version = "v7", format = "compact", uppercase = true });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(5, body.GetProperty("count").GetInt32());
            Assert.Equal("v7", body.RequiredString("version"));
            Assert.Equal("compact", body.RequiredString("format"));
            Assert.Equal(74, body.GetProperty("randomBits").GetInt32());

            var values = Values(body);

            Assert.Equal(5, values.Length);
            Assert.All(values, value => Assert.Equal(32, value.Length));
            Assert.All(
                values,
                value => Assert.True(
                    value[12] == '7' && value.All(character =>
                        char.IsAsciiDigit(character) || character is >= 'A' and <= 'F'),
                    "An uppercase compact version 7 UUID was not written as expected."));
            Assert.Equal(5, values.Distinct(StringComparer.Ordinal).Count());
        }

        [Theory]
        [InlineData("v9", null, "Unsupported UUID version")]
        [InlineData(null, "hex", "Unsupported UUID format")]
        public async Task An_unknown_uuid_option_name_is_a_bad_request_that_lists_the_supported_ones(
            string? version,
            string? format,
            string expected)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/uuid",
                new { version, format });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            // An unknown name is refused rather than quietly falling back, and the message says what works.
            Assert.Contains(expected, detail, StringComparison.Ordinal);
            Assert.Contains("Supported values:", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(101)]
        public async Task A_uuid_count_outside_the_supported_range_is_a_bad_request(int count)
        {
            var (response, body) = await _client.PostJsonAsync("/api/identity/uuid", new { count });

            response.AssertProblem();
            Assert.Contains("between 1 and 100", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_totp_secret_route_returns_a_hundred_and_sixty_bit_sha1_secret_by_default()
        {
            var response = await _client.PostAsync("/api/identity/totp-secret", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(20, body.GetProperty("bytes").GetInt32());
            Assert.Equal(160d, body.GetProperty("entropyBits").GetDouble());
            Assert.Equal("SHA1", body.RequiredString("algorithm"));
            Assert.Equal(6, body.GetProperty("digits").GetInt32());
            Assert.Equal(30, body.GetProperty("periodSeconds").GetInt32());

            var secret = body.RequiredString("secret");

            // Only the shape is asserted, so no generated secret reaches the test output.
            Assert.True(
                secret.Length == 32
                && secret.All(character => Base32Alphabet.Contains(character, StringComparison.Ordinal)),
                "A generated TOTP secret was not 32 unpadded Base32 characters.");
        }

        [Theory]
        [InlineData("sha-256", "SHA256", 32)]
        [InlineData("SHA512", "SHA512", 64)]
        public async Task A_totp_secret_is_sized_for_the_hash_function_named_in_any_accepted_spelling(
            string requested,
            string expected,
            int expectedBytes)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-secret",
                new { algorithm = requested });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expected, body.RequiredString("algorithm"));
            Assert.Equal(expectedBytes, body.GetProperty("bytes").GetInt32());
        }

        [Fact]
        public async Task Two_totp_secrets_are_never_the_same()
        {
            var secrets = new List<string>();

            for (var attempt = 0; attempt < 10; attempt++)
            {
                var response = await _client.PostAsync("/api/identity/totp-secret", content: null);
                secrets.Add((await ApiClient.ReadJsonAsync(response)).RequiredString("secret"));
            }

            // Only the count is compared, so no generated secret reaches the test output.
            Assert.Equal(secrets.Count, secrets.Distinct(StringComparer.Ordinal).Count());
        }

        [Theory]
        [InlineData(8)]
        [InlineData(65)]
        public async Task A_totp_secret_size_outside_the_supported_range_is_a_bad_request(int bytes)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-secret",
                new { bytes });

            response.AssertProblem();
            Assert.Contains("between 16 and 64 bytes", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unknown_totp_algorithm_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-secret",
                new { algorithm = "md5" });

            response.AssertProblem();
            Assert.Contains(
                "Unsupported TOTP algorithm",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_authenticator_route_returns_a_uri_an_authenticator_can_read()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-authenticator",
                new { issuer = "Example Corp", account = "person@example.com" });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Example Corp", body.RequiredString("issuer"));
            Assert.Equal("person@example.com", body.RequiredString("account"));
            Assert.Equal(20, body.GetProperty("bytes").GetInt32());

            var uri = body.RequiredString("uri");
            var secret = body.RequiredString("secret");

            Assert.StartsWith(
                "otpauth://totp/Example%20Corp:person%40example.com?secret=",
                uri,
                StringComparison.Ordinal);
            Assert.Contains("&algorithm=SHA1", uri, StringComparison.Ordinal);
            Assert.Contains("&digits=6", uri, StringComparison.Ordinal);
            Assert.Contains("&period=30", uri, StringComparison.Ordinal);
            Assert.True(
                uri.Contains($"secret={secret}", StringComparison.Ordinal),
                "The enrollment URI did not carry the secret it was built around.");

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("picture of the second factor", StringComparison.Ordinal));
        }

        [Fact]
        public async Task An_enrollment_without_a_body_is_a_bad_request_naming_what_is_missing()
        {
            var response = await _client.PostAsync("/api/identity/totp-authenticator", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            response.AssertProblem();
            Assert.Contains("The issuer is required.", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_enrollment_without_an_account_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-authenticator",
                new { issuer = "Example" });

            response.AssertProblem();
            Assert.Contains(
                "The account name is required.",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_enrollment_label_containing_a_colon_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-authenticator",
                new { issuer = "Example:Corp", account = "person" });

            response.AssertProblem();
            Assert.Contains(
                "must not contain a colon",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_enrollment_given_both_a_secret_and_a_size_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-authenticator",
                new { issuer = "Example", account = "person", secret = Sha1Seed, bytes = 32 });

            response.AssertProblem();
            Assert.Contains(
                "Omit the size to use the supplied secret",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(59L, "287082")]
        [InlineData(1111111111L, "050471")]
        [InlineData(1234567890L, "005924")]
        public async Task The_code_route_reproduces_the_rfc_6238_six_digit_vectors(
            long unixTimeSeconds,
            string expected)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new { secret = Sha1Seed, unixTimeSeconds });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expected, body.RequiredString("code"));
            Assert.Equal(unixTimeSeconds, body.GetProperty("unixTimeSeconds").GetInt64());
            Assert.Equal(unixTimeSeconds / 30, body.GetProperty("counter").GetInt64());
        }

        [Fact]
        public async Task The_code_route_reproduces_an_eight_digit_sha512_vector()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new
                {
                    secret = Sha512Seed,
                    algorithm = "sha512",
                    digits = 8,
                    unixTimeSeconds = 1111111109L
                });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("25091201", body.RequiredString("code"));
            Assert.Equal("SHA512", body.RequiredString("algorithm"));
            Assert.Equal(8, body.GetProperty("digits").GetInt32());
        }

        [Fact]
        public async Task The_code_route_does_not_echo_the_secret_it_was_given()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new { secret = Sha1Seed, unixTimeSeconds = 59L });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            ApiClient.AssertHidesSecrets(body, ("secret that was submitted", Sha1Seed));

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains(
                    "verifies nothing and authenticates nobody",
                    StringComparison.Ordinal));
        }

        [Fact]
        public async Task The_code_route_requires_a_secret()
        {
            var response = await _client.PostAsync("/api/identity/totp-code", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            response.AssertProblem();
            Assert.Contains("The secret is required.", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_malformed_secret_is_a_bad_request_that_does_not_repeat_it()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new { secret = "GEZDGNBVGY3TQOJQ!" });

            response.AssertProblem();
            Assert.Equal("The secret is not valid Base32.", body.RequiredString("detail"));
        }

        [Fact]
        public async Task A_secret_below_the_rfc_floor_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new { secret = "MZXW6YTBOI======" });

            response.AssertProblem();
            Assert.Contains("at least 10 bytes", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_negative_time_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new { secret = Sha1Seed, unixTimeSeconds = -1L });

            response.AssertProblem();
            Assert.Contains("must not be negative", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_base32_route_encodes_text_and_says_it_is_not_encryption()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/base32",
                new { text = "foobar" });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("MZXW6YTBOI======", body.RequiredString("value"));
            Assert.Equal("Base32 (RFC 4648)", body.RequiredString("encoding"));
            Assert.Equal(6, body.GetProperty("bytes").GetInt32());
            Assert.Equal(16, body.GetProperty("length").GetInt32());

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("an encoding, not encryption", StringComparison.Ordinal));
        }

        [Fact]
        public async Task The_base32_route_can_drop_the_padding_and_lower_the_case()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/base32",
                new { text = "foobar", padding = false, lowercase = true });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("mzxw6ytboi", body.RequiredString("value"));
        }

        [Fact]
        public async Task The_base32_route_accepts_bytes_as_base64()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/base32",
                new { base64 = "Zm9vYmFy" });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("MZXW6YTBOI======", body.RequiredString("value"));
        }

        [Fact]
        public async Task The_base32_route_refuses_both_inputs_and_refuses_neither()
        {
            var (both, bothBody) = await _client.PostJsonAsync(
                "/api/identity/base32",
                new { text = "a", base64 = "YQ==" });

            both.AssertProblem();
            Assert.Contains("not both", bothBody.RequiredString("detail"), StringComparison.Ordinal);

            var neither = await _client.PostAsync("/api/identity/base32", content: null);
            var neitherBody = await ApiClient.ReadJsonAsync(neither);

            neither.AssertProblem();
            Assert.Contains(
                "Either text or Base64 bytes are required.",
                neitherBody.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_base32_route_refuses_malformed_base64()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/base32",
                new { base64 = "not valid base64!" });

            response.AssertProblem();
            Assert.Equal("The supplied bytes are not valid Base64.", body.RequiredString("detail"));
        }

        [Fact]
        public async Task The_test_card_route_lists_published_numbers_that_all_pass_the_luhn_check()
        {
            var (response, body) = await _client.GetJsonAsync("/api/identity/test-cards");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var cards = body.GetProperty("cards").EnumerateArray().ToArray();

            Assert.Equal(cards.Length, body.GetProperty("count").GetInt32());
            Assert.NotEmpty(cards);
            Assert.NotEmpty(body.GetProperty("brands").EnumerateArray());

            Assert.All(
                cards,
                card =>
                {
                    Assert.True(
                        card.GetProperty("luhnValid").GetBoolean(),
                        "A listed test card number does not pass the Luhn check.");

                    var number = card.RequiredString("number");

                    Assert.True(
                        number.All(char.IsAsciiDigit) && number.Length is >= 12 and <= 19,
                        "A listed test card number is not a plausible card number.");
                    Assert.Equal(number.Length, card.GetProperty("digits").GetInt32());
                });

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("published test numbers", StringComparison.Ordinal));
        }

        [Fact]
        public async Task The_test_card_route_can_be_narrowed_to_one_network()
        {
            var (response, body) = await _client.GetJsonAsync("/api/identity/test-cards?brand=AmEx");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var cards = body.GetProperty("cards").EnumerateArray().ToArray();

            Assert.NotEmpty(cards);
            Assert.All(
                cards,
                card =>
                {
                    Assert.Equal("amex", card.RequiredString("brand"));
                    Assert.Equal(4, card.GetProperty("securityCodeDigits").GetInt32());
                    Assert.Equal(15, card.GetProperty("digits").GetInt32());
                });
        }

        [Fact]
        public async Task An_unknown_card_brand_is_a_bad_request_that_lists_the_supported_ones()
        {
            var (response, body) = await _client.GetJsonAsync("/api/identity/test-cards?brand=notacard");

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported card brand", detail, StringComparison.Ordinal);
            Assert.Contains("visa", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_secret_can_be_generated_enrolled_and_used_to_produce_a_code()
        {
            // The whole flow a caller actually performs, end to end through HTTP.
            var generated = await _client.PostAsync("/api/identity/totp-secret", content: null);
            var secret = (await ApiClient.ReadJsonAsync(generated)).RequiredString("secret");

            var (enrolled, enrollment) = await _client.PostJsonAsync(
                "/api/identity/totp-authenticator",
                new { issuer = "Example", account = "person", secret });

            Assert.Equal(HttpStatusCode.OK, enrolled.StatusCode);
            Assert.True(
                string.Equals(secret, enrollment.RequiredString("secret"), StringComparison.Ordinal),
                "The enrollment was built around a different secret than the one supplied.");
            Assert.Equal(20, enrollment.GetProperty("bytes").GetInt32());

            var (computed, code) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new { secret = enrollment.RequiredString("secret"), unixTimeSeconds = 1_700_000_000L });

            Assert.Equal(HttpStatusCode.OK, computed.StatusCode);

            var value = code.RequiredString("code");

            Assert.True(
                value.Length == 6 && value.All(char.IsAsciiDigit),
                "The code produced from the enrolled secret was not six digits.");

            // The same secret written the way a person reads it back must produce the same code.
            var grouped = Enumerable
                .Range(0, secret.Length / 4)
                .Select(index => secret.Substring(index * 4, 4));

            var (again, repeated) = await _client.PostJsonAsync(
                "/api/identity/totp-code",
                new
                {
                    secret = string.Join("-", grouped).ToLowerInvariant(),
                    unixTimeSeconds = 1_700_000_000L
                });

            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
            Assert.Equal(value, repeated.RequiredString("code"));
        }

        [Fact]
        public async Task A_rejected_request_is_explained_without_exposing_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/identity/uuid",
                new { count = 9999 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("Exception", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SecureToolKitAPI", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", detail, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(PostOnlyRoutes))]
        public async Task A_get_request_to_a_generation_route_is_not_allowed(string route)
        {
            // A GET would put a TOTP secret in a URL, which is exactly what these routes are shaped to avoid.
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task A_post_is_not_allowed_on_the_card_listing()
        {
            var response = await _client.PostAsync("/api/identity/test-cards", content: null);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/identity/uuid",
                new StringContent("{\"count\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }

        /// <summary>The identifiers from a UUID response, as plain strings.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Values(JsonElement body) =>
            [.. body.GetProperty("values").EnumerateArray().Select(value => value.GetString() ?? string.Empty)];

        /// <summary>The warnings from a response, as plain strings.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Warnings(JsonElement body) =>
            [.. body.GetProperty("warnings").EnumerateArray().Select(warning => warning.GetString() ?? string.Empty)];
    }
}
