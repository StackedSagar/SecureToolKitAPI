using System.Net;
using System.Text;
using System.Text.Json;
using SecureToolKitAPI.Application;
using Xunit;

namespace SecureToolKitAPI.Tests.Integration
{
    /// <summary>
    /// The password endpoints over HTTP: that every route answers, that the options in the body are
    /// applied, that bad input becomes a problem response rather than an exception, and that the preset
    /// listing exposes no secret.
    /// </summary>
    /// <remarks>
    /// Generated values are never asserted against a fixed expectation and never printed: the assertions
    /// check shape, length and character class. Nothing here sends a secret to the API, so nothing here
    /// can leak one.
    /// </remarks>
    [Collection(ApiCollection.Name)]
    public class PasswordEndpointTests(ApiFactory factory)
    {
        private readonly HttpClient _client = factory.CreateClient();

        /// <summary>Every route that returns a generated value, with the length it defaults to.</summary>
        public static TheoryData<string, int> FixedLengthRoutes => new()
        {
            { "/api/password", 16 },
            { "/api/password/master", 24 },
            { "/api/password/wifi", 20 },
            { "/api/password/gaming", 12 },
            { "/api/password/temporary", 10 }
        };

        /// <summary>Routes whose length depends on the words or syllables chosen rather than being fixed.</summary>
        public static TheoryData<string> VariableLengthRoutes => new()
        {
            "/api/password/passphrase",
            "/api/password/memorable",
            "/api/password/pronounceable",
            "/api/password/pin",
            "/api/password/username"
        };

        [Theory]
        [MemberData(nameof(FixedLengthRoutes))]
        public async Task Each_fixed_length_route_answers_without_a_body_and_uses_its_documented_length(
            string route,
            int expectedLength)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expectedLength, body.GetProperty("length").GetInt32());
            Assert.Equal(expectedLength, body.RequiredString("value").Length);
            Assert.True(body.GetProperty("entropyBits").GetDouble() > 0d, "The response reported no entropy.");
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("strength")), "The strength was missing.");
            Assert.False(string.IsNullOrWhiteSpace(body.RequiredString("composition")), "The composition was missing.");
        }

        [Theory]
        [MemberData(nameof(VariableLengthRoutes))]
        public async Task Each_variable_length_route_answers_without_a_body(string route)
        {
            var response = await _client.PostAsync(route, content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(body.RequiredString("value").Length, body.GetProperty("length").GetInt32());
            Assert.True(body.GetProperty("entropyBits").GetDouble() > 0d, "The response reported no entropy.");
        }

        [Fact]
        public async Task The_password_route_reports_no_preset_when_none_was_used()
        {
            var (_, body) = await _client.PostJsonAsync("/api/password", new { length = 24 });

            Assert.False(
                body.TryGetProperty("preset", out _),
                "A password generated from explicit options reported a preset it did not come from.");
        }

        [Theory]
        [InlineData(4)]
        [InlineData(16)]
        [InlineData(64)]
        [InlineData(512)]
        public async Task The_requested_length_is_applied(int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/password", new { length });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(length, body.GetProperty("length").GetInt32());
            Assert.Equal(length, body.RequiredString("value").Length);
        }

        [Fact]
        public async Task A_character_set_is_included_unless_the_caller_excludes_it()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password",
                new { length = 32, includeSymbols = false, includeDigits = false });

            var value = body.RequiredString("value");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(value.All(char.IsAsciiLetter), "A letters-only password contained a digit or a symbol.");
            Assert.Contains("lowercase, uppercase", body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task Excluding_ambiguous_characters_is_reported_and_applied()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password",
                new { length = 40, excludeAmbiguous = true });

            const string ambiguous = "0O1lI5S2Z8B";

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(
                body.RequiredString("value").All(character => !ambiguous.Contains(character, StringComparison.Ordinal)),
                "An unambiguous password contained an easily confused character.");

            Assert.Contains("ambiguous characters excluded", body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task Excluding_every_character_set_is_a_bad_request_rather_than_an_empty_password()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password",
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

        [Theory]
        [InlineData(3)]
        [InlineData(0)]
        [InlineData(-5)]
        [InlineData(513)]
        public async Task A_length_outside_the_supported_range_is_a_bad_request(int length)
        {
            var (response, body) = await _client.PostJsonAsync("/api/password", new { length });

            response.AssertProblem();
            Assert.Contains("between 4 and 512", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_rejected_request_is_explained_without_exposing_how_the_api_is_built()
        {
            var (response, body) = await _client.PostJsonAsync("/api/password", new { length = 9999 });

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.DoesNotContain("Exception", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SecureToolKitAPI", detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Bulk_generation_returns_the_requested_number_of_distinct_passwords()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password/bulk",
                new { count = 25, password = new { length = 20, includeSymbols = false } });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(25, body.GetProperty("count").GetInt32());

            var passwords = body.GetProperty("passwords").EnumerateArray().ToArray();

            Assert.Equal(25, passwords.Length);
            Assert.All(passwords, password => Assert.Equal(20, password.GetProperty("length").GetInt32()));

            // Only the count is compared, so no generated value reaches the test output.
            Assert.Equal(
                25,
                passwords.Select(password => password.RequiredString("value")).Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public async Task Bulk_generation_uses_its_defaults_when_no_body_is_sent()
        {
            var response = await _client.PostAsync("/api/password/bulk", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(10, body.GetProperty("count").GetInt32());
            Assert.Equal(10, body.GetProperty("passwords").GetArrayLength());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(101)]
        public async Task A_bulk_count_outside_the_supported_range_is_a_bad_request(int count)
        {
            var (response, body) = await _client.PostJsonAsync("/api/password/bulk", new { count });

            response.AssertProblem();
            Assert.Contains("between 1 and 100", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_bulk_request_with_invalid_password_options_is_a_bad_request()
        {
            var (response, _) = await _client.PostJsonAsync(
                "/api/password/bulk",
                new { count = 5, password = new { length = 1 } });

            response.AssertProblem();
        }

        [Fact]
        public async Task A_passphrase_uses_the_requested_words_and_separator()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password/passphrase",
                new { words = 8, separator = "_", capitalize = true });

            var value = body.RequiredString("value");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(8, value.Split('_').Length);
            Assert.True(
                value.Split('_').All(word => char.IsAsciiLetterUpper(word[0])),
                "A word in the capitalised passphrase did not start with an uppercase letter.");

            Assert.Contains("8 words", body.RequiredString("composition"), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(2)]
        [InlineData(25)]
        public async Task A_passphrase_word_count_outside_the_supported_range_is_a_bad_request(int words)
        {
            var (response, body) = await _client.PostJsonAsync("/api/password/passphrase", new { words });

            response.AssertProblem();
            Assert.Contains("between 3 and 24", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_passphrase_separator_containing_whitespace_is_a_bad_request()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password/passphrase",
                new { words = 5, separator = " " });

            response.AssertProblem();
            Assert.Contains("whitespace", body.RequiredString("detail"), StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_memorable_passphrase_is_four_hyphenated_words_with_a_digit()
        {
            var response = await _client.PostAsync("/api/password/memorable", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            var value = body.RequiredString("value");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(4, value.Split('-').Length);
            Assert.True(char.IsAsciiDigit(value[^1]), "The memorable passphrase did not end with a digit.");
            Assert.True(char.IsAsciiLetterUpper(value[0]), "The memorable passphrase was not capitalised.");
        }

        [Fact]
        public async Task A_pin_contains_only_digits_and_says_it_is_weak()
        {
            var (response, body) = await _client.PostJsonAsync("/api/password/pin", new { length = 8 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(8, body.GetProperty("length").GetInt32());
            Assert.True(body.RequiredString("value").All(char.IsAsciiDigit), "The PIN contained a non-digit.");
            Assert.Contains(Warnings(body), warning => warning.Contains("weak by construction", StringComparison.Ordinal));
        }

        [Fact]
        public async Task A_pronounceable_value_says_what_it_trades_away()
        {
            var (response, body) = await _client.PostJsonAsync("/api/password/pronounceable", new { syllables = 5 });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("trades strength for readability", StringComparison.Ordinal));
        }

        [Fact]
        public async Task A_suggested_username_is_marked_as_a_public_identifier()
        {
            var (response, body) = await _client.PostJsonAsync(
                "/api/password/username",
                new { words = 2, separator = ".", includeNumber = false });

            var value = body.RequiredString("value");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(2, value.Split('.').Length);
            Assert.Contains(Warnings(body), warning => warning.Contains("not a secret", StringComparison.Ordinal));
        }

        [Fact]
        public async Task The_preset_listing_describes_every_preset_and_contains_no_generated_value()
        {
            var (response, body) = await _client.GetJsonAsync("/api/password/presets");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var presets = body.EnumerateArray().ToArray();

            Assert.Equal(PasswordPresetCatalog.All.Count, presets.Length);

            // Ordered by name, so the listing is stable for a caller that renders it as-is.
            Assert.Equal(
                PasswordPresetCatalog.Names,
                presets.Select(preset => preset.RequiredString("name")).ToArray());

            Assert.All(presets, preset =>
            {
                Assert.False(string.IsNullOrWhiteSpace(preset.RequiredString("description")), "A preset had no description.");
                Assert.False(string.IsNullOrWhiteSpace(preset.RequiredString("composition")), "A preset had no composition.");
                Assert.True(preset.GetProperty("length").GetInt32() >= 4, "A preset reported an unusable length.");

                // Describing a preset must not require generating a password, so there is nothing secret
                // in this response.
                Assert.False(preset.TryGetProperty("value", out _), "The preset listing returned a generated value.");
            });
        }

        [Theory]
        [InlineData("password", 16)]
        [InlineData("master", 24)]
        [InlineData("WIFI", 20)]
        [InlineData("Easy-To-Read", 20)]
        [InlineData("numbers-only", 12)]
        [InlineData("32-character", 32)]
        public async Task A_preset_can_be_generated_by_name_whatever_its_casing(string preset, int expectedLength)
        {
            var response = await _client.PostAsync($"/api/password/presets/{preset}", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expectedLength, body.GetProperty("length").GetInt32());

            // The catalogue's own spelling is echoed back, not the caller's.
            Assert.Equal(preset, body.RequiredString("preset"), ignoreCase: true);
            Assert.Contains(body.RequiredString("preset"), PasswordPresetCatalog.Names);
        }

        [Fact]
        public async Task A_preset_that_is_weaker_than_the_default_says_so()
        {
            var response = await _client.PostAsync("/api/password/presets/numbers-only", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(Warnings(body), warning => warning.Contains("Digits alone", StringComparison.Ordinal));
        }

        [Fact]
        public async Task A_named_route_reports_the_preset_it_used()
        {
            var response = await _client.PostAsync("/api/password/temporary", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("temporary", body.RequiredString("preset"));
            Assert.Contains(
                Warnings(body),
                warning => warning.Contains("used once and changed immediately", StringComparison.Ordinal));
        }

        [Fact]
        public async Task An_unknown_preset_is_refused_and_the_supported_names_are_listed()
        {
            var response = await _client.PostAsync("/api/password/presets/not-a-preset", content: null);
            var body = await ApiClient.ReadJsonAsync(response);

            response.AssertProblem();

            var detail = body.RequiredString("detail");

            Assert.Contains("Unsupported preset", detail, StringComparison.Ordinal);
            Assert.Contains("wifi", detail, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Repeated_requests_do_not_return_the_same_password()
        {
            var values = new List<string>();

            for (var attempt = 0; attempt < 10; attempt++)
            {
                var (_, body) = await _client.PostJsonAsync("/api/password", new { length = 24 });
                values.Add(body.RequiredString("value"));
            }

            Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public async Task A_get_request_to_a_generation_route_is_not_allowed()
        {
            var response = await _client.GetAsync("/api/password");

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }

        [Fact]
        public async Task Malformed_json_is_reported_as_a_bad_request()
        {
            var response = await _client.PostAsync(
                "/api/password",
                new StringContent("{\"length\":", Encoding.UTF8, "application/json"));

            response.AssertProblem();
        }

        /// <summary>The warnings from a password response, as plain strings.</summary>
        /// <param name="body">The parsed response body.</param>
        private static string[] Warnings(JsonElement body) =>
            [.. body.GetProperty("warnings").EnumerateArray().Select(warning => warning.GetString() ?? string.Empty)];
    }
}
