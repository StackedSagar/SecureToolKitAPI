using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The recovery endpoints over HTTP: that every route answers, that the options in the body are
    /// applied, that unusable options become a problem response rather than an exception, and that the
    /// strength check never repeats the password it was given.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Generated codes and keys are never asserted against a fixed expectation and never printed: the
    /// assertions check count, length and character class. The password used by the strength tests is a
    /// literal written for the test and is checked for absence from the response rather than compared.
    /// </para>
    /// <para>
    /// Every route is POST with the values in the body, which is what keeps recovery credentials and
    /// passwords out of server logs, proxy logs and browser history. The wrong-verb test exists to keep it
    /// that way.
    /// </para>
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class RecoveryEndpointTests(ApiFactory factory)
    {
        /// <summary>The routes that answer with their documented defaults when no body is sent.</summary>
        public static TheoryData<string> DefaultedRoutes => new()
        {
            "/api/recovery/backup-codes",
            "/api/recovery/recovery-key",
            "/api/recovery/entropy"
        };

        /// <summary>
        /// A password written for these tests, containing no run of characters that a description of it
        /// could plausibly also contain. Not a credential.
        /// </summary>
        private const string TestPassword = "Wk4#Zx9$Jm2%Qr7&";

        private readonly HttpClient _client = factory.CreateClient();

        [Theory]
        [MemberData(nameof(DefaultedRoutes))]
        public async Task Each_route_answers_without_a_body(string route)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("strength")), "The strength was missing.");
            Assert.False(
                string.IsNullOrWhiteSpace(body.RequiredString("composition")),
                "The composition was missing.");
        }

        [Fact]
        public async Task The_backup_codes_route_returns_ten_grouped_codes_by_default()
        {
            var response = await _client.PostAsync("/api/recovery/backup-codes", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(10, body.GetProperty("count").GetInt32());
            Assert.Equal(10, body.GetProperty("length").GetInt32());
            Assert.Equal(50d, body.GetProperty("entropyBitsPerCode").GetDouble());

            var codes = Codes(body);

            // Ten characters of randomness written as two groups of five, so eleven characters on the wire.
            Assert.Equal(10, codes.Length);
            Assert.All(codes, code => Assert.Equal(11, code.Length));
            Assert.Equal(10, codes.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public async Task The_requested_backup_code_options_are_applied()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/backup-codes",
                new { count = 5, length = 12, format = "numeric", groupSize = 4 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(5, body.GetProperty("count").GetInt32());
            Assert.Equal(12, body.GetProperty("length").GetInt32());

            var codes = Codes(body);

            Assert.Equal(5, codes.Length);
            Assert.All(codes, code => Assert.Equal(14, code.Length));
            Assert.All(
                codes,
                code => Assert.True(
                    code.All(character => character == '-' || char.IsAsciiDigit(character)),
                    "A numeric backup code requested over HTTP contained something other than a digit."));
        }

        [Fact]
        public async Task A_group_size_of_zero_returns_the_codes_unbroken()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/backup-codes",
                new { length = 16, groupSize = 0 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.All(
                Codes(body),
                code => Assert.True(
                    code.Length == 16 && !code.Contains('-', StringComparison.Ordinal),
                    "An ungrouped backup code was still broken into groups."));
        }

        [Theory]
        [InlineData("Numeric")]
        [InlineData("numeric")]
        [InlineData("NUMERIC")]
        public async Task The_format_name_is_matched_without_regard_to_case(string format)
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/backup-codes",
                new { count = 1, format });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("digits (10 character alphabet)", body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task An_unknown_format_is_a_bad_request_that_lists_what_is_supported()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/backup-codes",
                new { format = "roman-numerals" });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported backup code format", detail, StringComparison.Ordinal);
            Assert.Contains("Alphanumeric", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(51)]
        public async Task A_backup_code_count_outside_the_supported_range_is_a_bad_request(int count)
        {
            var (response, body) = await _client.PostJsonAsync("/api/recovery/backup-codes", new { count });

            response.AssertProblem();
            Assert.Contains("between 1 and 50", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(5)]
        [InlineData(33)]
        public async Task A_backup_code_length_outside_the_supported_range_is_a_bad_request(int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/recovery/backup-codes", new { length });

            response.AssertProblem();
            Assert.Contains("between 6 and 32 characters", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_recovery_key_route_returns_five_groups_of_five_by_default()
        {
            var response = await _client.PostAsync("/api/recovery/recovery-key", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(25, body.GetProperty("characters").GetInt32());
            Assert.Equal(5, body.GetProperty("groups").GetInt32());
            Assert.Equal(125d, body.GetProperty("entropyBits").GetDouble());

            var value = body.RequiredString("value");

            Assert.Equal(29, value.Length);
            Assert.Equal(5, value.Split('-').Length);
        }

        [Fact]
        public async Task The_requested_recovery_key_options_are_applied()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/recovery-key",
                new { groups = 8, groupSize = 8 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(64, body.GetProperty("characters").GetInt32());
            Assert.Equal(8, body.GetProperty("groups").GetInt32());
            Assert.Equal(320d, body.GetProperty("entropyBits").GetDouble());
            Assert.Equal(71, body.RequiredString("value").Length);
        }

        [Fact]
        public async Task Two_recovery_keys_are_never_the_same()
        {
            var values = new List<string>();

            for (var attempt = 0; attempt < 10; attempt++)
            {
                var response = await _client.PostAsync("/api/recovery/recovery-key", content: null);
                values.Add((await ApiClient.ReadJsonAsync(response)).RequiredString("value"));
            }

            // Only the count is compared, so no generated key reaches the test output.
            Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
        }

        [Theory]
        [InlineData(1)]
        [InlineData(17)]
        public async Task A_recovery_key_group_count_outside_the_supported_range_is_a_bad_request(int groups)
        {
            var (response, body) = await _client.PostJsonAsync("/api/recovery/recovery-key", new { groups });

            response.AssertProblem();
            Assert.Contains("between 2 and 16", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_strength_route_assesses_a_password_without_repeating_any_of_it()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/strength",
                new { password = TestPassword });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(TestPassword.Length, body.GetProperty("length").GetInt32());
            Assert.True(body.GetProperty("entropyBits").GetDouble() > 0d, "The response reported no entropy.");
            Assert.True(body.GetProperty("guessesLog10").GetDouble() > 0d, "The response reported no guess count.");

            ApiClient.AssertHidesSecrets(body, ("password that was submitted", TestPassword));
        }

        [Fact]
        public async Task The_strength_route_says_the_figure_is_an_upper_bound()
        {
            var (_, body) = await _client.PostJsonAsync(
                "/api/recovery/strength",
                new { password = TestPassword });

            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("upper bound", StringComparison.Ordinal));
            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("appeared in a breach", StringComparison.Ordinal));
        }

        [Fact]
        public async Task A_patterned_password_is_scored_below_an_unpatterned_one_of_the_same_length()
        {
            var (_, patterned) = await _client.PostJsonAsync(
                "/api/recovery/strength",
                new { password = new string('a', TestPassword.Length) });

            var (_, unpatterned) = await _client.PostJsonAsync(
                "/api/recovery/strength",
                new { password = TestPassword });

            Assert.True(
                patterned.GetProperty("entropyBits").GetDouble()
                    < unpatterned.GetProperty("entropyBits").GetDouble(),
                "One character repeated scored as high as an unpatterned password of the same length.");

            Assert.NotEmpty(patterned.GetProperty("findings").EnumerateArray());
        }

        [Fact]
        public async Task The_strength_route_requires_a_password()
        {
            var response = await _client.PostAsync("/api/recovery/strength", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            response.AssertProblem();
            Assert.Contains("A password is required.", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_password_longer_than_the_api_generates_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/strength",
                new { password = new string('a', 513) });

            response.AssertProblem();
            Assert.Contains("at most 512 characters", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_entropy_route_describes_sixteen_characters_over_every_set_by_default()
        {
            var response = await _client.PostAsync("/api/recovery/entropy", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(16, body.GetProperty("count").GetInt32());
            Assert.Equal(84, body.GetProperty("alphabetSize").GetInt32());
            Assert.Equal(6.4d, body.GetProperty("entropyBitsPerCharacter").GetDouble());
            Assert.Equal(102.3d, body.GetProperty("entropyBits").GetDouble());
            Assert.Equal(
                "lowercase, uppercase, digits, symbols (84 character alphabet)",
                body.RequiredString("composition"));
        }

        [Fact]
        public async Task Naming_one_character_set_leaves_the_others_included()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/entropy",
                new { includeUppercase = false, includeSymbols = false });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(36, body.GetProperty("alphabetSize").GetInt32());
            Assert.Equal("lowercase, digits (36 character alphabet)", body.RequiredString("composition"));
        }

        [Fact]
        public async Task An_alphabet_named_by_size_alone_is_accepted()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/entropy",
                new { count = 6, alphabetSize = 7776 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(7776, body.GetProperty("alphabetSize").GetInt32());
            Assert.Equal(77.5d, body.GetProperty("entropyBits").GetDouble());
            Assert.Equal("7776 character alphabet", body.RequiredString("composition"));
        }

        [Fact]
        public async Task Naming_the_alphabet_both_ways_at_once_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/entropy",
                new { count = 6, alphabetSize = 7776, includeDigits = true });

            response.AssertProblem();
            Assert.Contains(
                "Supply either character sets or an alphabet size, not both.",
                body.RequiredString("detail"),
                StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4097)]
        public async Task A_character_count_outside_the_supported_range_is_a_bad_request(int count)
        {
            var (response, body) = await _client.PostJsonAsync("/api/recovery/entropy", new { count });

            response.AssertProblem();
            Assert.Contains("between 1 and 4096", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task Excluding_every_character_set_is_a_bad_request_rather_than_a_zero_bit_answer()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/entropy",
                new
                {
                    includeLowercase = false,
                    includeUppercase = false,
                    includeDigits = false,
                    includeSymbols = false
                });

            response.AssertProblem();
            Assert.Contains("At least one character set", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_rejected_request_is_explained_without_exposing_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/recovery/backup-codes",
                new { count = 9999 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("Exception", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SecureToolKitAPI", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", detail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("/api/recovery/backup-codes")]
        [InlineData("/api/recovery/recovery-key")]
        [InlineData("/api/recovery/strength")]
        [InlineData("/api/recovery/entropy")]
        public async Task A_get_request_is_not_allowed_on_any_recovery_route(string route)
        {
            // A GET would put a recovery credential or a password in a URL, which is exactly what these
            // routes are shaped to avoid.
            var response = await _client.GetAsync(route);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/recovery/backup-codes",
                new StringContent("{\"count\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }

        /// <summary>The codes from a backup code response, as plain strings.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Codes(JsonElement body) =>
            [.. body.GetProperty("codes").EnumerateArray().Select(code => code.GetString() ?? string.Empty)];

        /// <summary>The warnings from a response, as plain strings.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Warnings(JsonElement body) =>
            [.. body.GetProperty("warnings").EnumerateArray().Select(warning => warning.GetString() ?? string.Empty)];
    }
}
