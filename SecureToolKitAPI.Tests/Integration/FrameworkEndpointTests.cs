using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The framework key endpoints over HTTP: that every route answers, that the options in the body are
    /// applied, that each value comes back in the shape the framework it was generated for accepts, and that
    /// unusable options become a problem response rather than an exception.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Generated values are never asserted against a fixed expectation and never printed: the assertions
    /// check length, character class, prefix and decoded size. Where a value has to be checked for absence
    /// from a field, the comparison is a boolean with a message naming the field.
    /// </para>
    /// <para>
    /// Every route is POST with the options in the body, because every one returns secret material and a URL
    /// ends up in server logs, proxy logs and browser history. The wrong-verb test exists to keep it that
    /// way.
    /// </para>
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class FrameworkEndpointTests(ApiFactory factory)
    {
        /// <summary>The routes that answer with their documented defaults when no body is sent.</summary>
        public static TheoryData<string> DefaultedRoutes => new()
        {
            "/api/framework/django",
            "/api/framework/flask",
            "/api/framework/laravel",
            "/api/framework/wordpress-salts"
        };

        /// <summary>The prefix Laravel requires in front of a Base64 encoded application key.</summary>
        private const string LaravelPrefix = "base64:";

        private readonly HttpClient _client = factory.CreateClient();

        [Theory]
        [MemberData(nameof(DefaultedRoutes))]
        public async Task Each_route_answers_without_a_body(string route)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.False(
                string.IsNullOrWhiteSpace(body.RequiredString("framework")),
                "The framework name was missing.");
            Assert.False(
                string.IsNullOrWhiteSpace(body.RequiredString("composition")),
                "The composition was missing.");
            Assert.False(
                string.IsNullOrWhiteSpace(body.RequiredString("strength")),
                "The strength was missing.");
            Assert.NotEmpty(body.GetProperty("warnings").EnumerateArray());
        }

        [Fact]
        public async Task The_django_route_returns_the_fifty_character_key_django_itself_produces()
        {
            var response = await _client.PostAsync("/api/framework/django", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Django", body.RequiredString("framework"));
            Assert.Equal("SECRET_KEY", body.RequiredString("setting"));
            Assert.Equal(50, body.GetProperty("length").GetInt32());
            Assert.Equal(282.2d, body.GetProperty("entropyBits").GetDouble());
            Assert.Equal(50, body.RequiredString("value").Length);

            // Only Laravel sizes its key by a cipher, so nothing here should report one.
            Assert.False(
                body.TryGetProperty("cipher", out _),
                "The Django response carried a cipher, which only Laravel's key has.");
        }

        [Theory]
        [InlineData(32, 180.6d)]
        [InlineData(64, 361.2d)]
        [InlineData(128, 722.4d)]
        public async Task The_requested_django_length_is_applied(int length, double expectedBits)
        {
            var (response, body) = await _client.PostJsonAsync("/api/framework/django", new { length });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.GetProperty("length").GetInt32());
            Assert.Equal(length, body.RequiredString("value").Length);
            Assert.Equal(expectedBits, body.GetProperty("entropyBits").GetDouble());
        }

        [Theory]
        [InlineData(31)]
        [InlineData(129)]
        public async Task A_django_length_outside_the_supported_range_is_a_bad_request(int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/framework/django", new { length });

            response.AssertProblem();
            Assert.Contains(
                "between 32 and 128 characters",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_flask_route_returns_what_secrets_token_hex_would_have_produced()
        {
            var response = await _client.PostAsync("/api/framework/flask", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Flask", body.RequiredString("framework"));
            Assert.Equal("SECRET_KEY", body.RequiredString("setting"));
            Assert.Equal(64, body.GetProperty("length").GetInt32());
            Assert.Equal(256d, body.GetProperty("entropyBits").GetDouble());
            Assert.Equal(
                "256 random bits, hexadecimal (64 characters)",
                body.RequiredString("composition"));

            Assert.True(
                body.RequiredString("value").All(Uri.IsHexDigit),
                "The default Flask key contained something that is not a hexadecimal digit.");
        }

        [Theory]
        [InlineData("base64", 44)]
        [InlineData("base64url", 43)]
        [InlineData("hexUpper", 64)]
        [InlineData("base62", 43)]
        public async Task The_requested_flask_encoding_is_applied(string encoding, int expectedLength)
        {
            var (response, body) = await _client.PostJsonAsync("/api/framework/flask", new { encoding });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expectedLength, body.GetProperty("length").GetInt32());
            Assert.Equal(expectedLength, body.RequiredString("value").Length);
        }

        [Theory]
        [InlineData("HEX")]
        [InlineData("hex")]
        [InlineData("Hex")]
        public async Task The_flask_encoding_name_is_matched_without_regard_to_case(string encoding)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/framework/flask",
                new { bytes = 16, encoding });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("128 random bits, hexadecimal (32 characters)", body.RequiredString("composition"));
        }

        [Fact]
        public async Task An_unknown_flask_encoding_is_a_bad_request_that_lists_what_is_supported()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/framework/flask",
                new { encoding = "rot13" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported encoding", detail, StringComparison.Ordinal);
            Assert.Contains("Base64Url", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(15)]
        [InlineData(129)]
        public async Task A_flask_size_outside_the_supported_range_is_a_bad_request(int bytes)
        {
            var (response, body) = await _client.PostJsonAsync("/api/framework/flask", new { bytes });

            response.AssertProblem();
            Assert.Contains("between 16 and 128 bytes", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_laravel_route_returns_a_key_sized_for_laravels_default_cipher()
        {
            var response = await _client.PostAsync("/api/framework/laravel", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Laravel", body.RequiredString("framework"));
            Assert.Equal("APP_KEY", body.RequiredString("setting"));
            Assert.Equal("aes-256-cbc", body.RequiredString("cipher"));
            Assert.Equal(256d, body.GetProperty("entropyBits").GetDouble());

            AssertLaravelKeyDecodesTo(body, expectedBytes: 32, expectedLength: 51);
        }

        [Theory]
        [InlineData("aes-128-cbc", "aes-128-cbc", 16, 31)]
        [InlineData("AES256GCM", "aes-256-gcm", 32, 51)]
        [InlineData("aes_128_gcm", "aes-128-gcm", 16, 31)]
        public async Task The_requested_laravel_cipher_decides_the_key_length(
            string cipher,
            string expectedName,
            int expectedBytes,
            int expectedLength)
        {
            var (response, body) = await _client.PostJsonAsync("/api/framework/laravel", new { cipher });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expectedName, body.RequiredString("cipher"));
            Assert.Equal(expectedBytes * 8d, body.GetProperty("entropyBits").GetDouble());

            AssertLaravelKeyDecodesTo(body, expectedBytes, expectedLength);
        }

        [Fact]
        public async Task An_unknown_laravel_cipher_is_a_bad_request_that_lists_what_is_supported()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/framework/laravel",
                new { cipher = "blowfish" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported cipher", detail, StringComparison.Ordinal);
            Assert.Contains("Aes256Cbc", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_wordpress_route_returns_the_eight_constants_wordpress_reads()
        {
            var response = await _client.PostAsync("/api/framework/wordpress-salts", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("WordPress", body.RequiredString("framework"));
            Assert.Equal(8, body.GetProperty("count").GetInt32());
            Assert.Equal(64, body.GetProperty("length").GetInt32());
            Assert.Equal(417.5d, body.GetProperty("entropyBitsPerValue").GetDouble());

            Assert.Equal(
                new[]
                {
                    "AUTH_KEY",
                    "SECURE_AUTH_KEY",
                    "LOGGED_IN_KEY",
                    "NONCE_KEY",
                    "AUTH_SALT",
                    "SECURE_AUTH_SALT",
                    "LOGGED_IN_SALT",
                    "NONCE_SALT"
                },
                Names(body));

            var values = Values(body);

            Assert.Equal(8, values.Length);
            Assert.All(values, value => Assert.Equal(64, value.Length));
            Assert.Equal(8, values.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public async Task The_wordpress_configuration_block_defines_each_constant_on_its_own_line()
        {
            var response = await _client.PostAsync("/api/framework/wordpress-salts", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            var configuration = body.RequiredString("configuration");
            var lines = configuration.Split('\n');

            Assert.Equal(8, lines.Length);
            Assert.All(
                Names(body),
                name => Assert.True(
                    configuration.Contains($"define( '{name}',", StringComparison.Ordinal),
                    $"The configuration block did not define {name}."));

            // Four apostrophes per line — two around the name, two around the value — and no more, so a
            // stray apostrophe here would be a value breaking out of its quotes.
            Assert.Equal(32, configuration.Count(character => character == '\''));
        }

        [Fact]
        public async Task The_requested_wordpress_length_is_applied_to_every_value()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/framework/wordpress-salts",
                new { length = 32 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(32, body.GetProperty("length").GetInt32());
            Assert.Equal(208.8d, body.GetProperty("entropyBitsPerValue").GetDouble());
            Assert.All(Values(body), value => Assert.Equal(32, value.Length));
        }

        [Theory]
        [InlineData(31)]
        [InlineData(129)]
        public async Task A_wordpress_length_outside_the_supported_range_is_a_bad_request(int length)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/framework/wordpress-salts",
                new { length });

            response.AssertProblem();
            Assert.Contains(
                "between 32 and 128 characters",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Fact]
        public async Task Two_calls_to_the_same_route_never_return_the_same_value()
        {
            var values = new List<string>();

            for (var attempt = 0; attempt < 10; attempt++)
            {
                var response = await _client.PostAsync("/api/framework/django", content: null);
                values.Add((await ApiClient.ReadJsonAsync(response)).RequiredString("value"));
            }

            // Only the count is compared, so no generated key reaches the test output.
            Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public async Task A_rejected_request_is_explained_without_exposing_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/framework/wordpress-salts",
                new { length = 9999 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("Exception", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SecureToolKitAPI", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", detail, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(DefaultedRoutes))]
        public async Task A_get_request_is_not_allowed_on_any_framework_route(string route)
        {
            // A GET would put a framework secret in a URL, which is exactly what these routes are shaped to
            // avoid.
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/framework/django",
                new StringContent("{\"length\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }

        /// <summary>
        /// Asserts the Laravel key carries the prefix Laravel looks for and decodes to exactly the length
        /// the cipher requires, which is the check that decides whether the application boots.
        /// </summary>
        /// <param name="body">The parsed response body.</param>
        /// <param name="expectedBytes">Bytes the configured cipher's key must contain.</param>
        /// <param name="expectedLength">Characters in the whole value, prefix included.</param>
        private static void AssertLaravelKeyDecodesTo(JsonElement body, int expectedBytes, int expectedLength)
        {
            var value = body.RequiredString("value");

            Assert.True(
                value.StartsWith(LaravelPrefix, StringComparison.Ordinal),
                "The Laravel key did not start with the base64: prefix Laravel looks for.");

            // Decoding here is the same operation Laravel performs when it reads APP_KEY, so this is the
            // assertion that says the value is usable rather than merely well shaped.
            Assert.Equal(expectedBytes, Convert.FromBase64String(value[LaravelPrefix.Length..]).Length);
            Assert.Equal(expectedLength, value.Length);
            Assert.Equal(expectedLength, body.GetProperty("length").GetInt32());
        }

        /// <summary>The constant names from a WordPress response, in the order they were returned.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Names(JsonElement body) =>
            [
                .. body.GetProperty("salts")
                    .EnumerateArray()
                    .Select(salt => salt.GetProperty("name").GetString() ?? string.Empty)
            ];

        /// <summary>The generated values from a WordPress response.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Values(JsonElement body) =>
            [
                .. body.GetProperty("salts")
                    .EnumerateArray()
                    .Select(salt => salt.GetProperty("value").GetString() ?? string.Empty)
            ];
    }
}
