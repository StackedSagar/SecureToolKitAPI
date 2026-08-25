using SecureToolKitAPI.Application;
using SecureToolKitAPI.Cryptography.Abstractions;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The published test card catalogue: that every number in it is a plausible card number that passes the
    /// Luhn check, that a brand resolves however it was written, that an unknown brand is refused, and that
    /// the Luhn implementation actually rejects the mistakes it exists to catch.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nothing here is secret. These are the numbers the card networks publish for testing: they are not
    /// issued to anyone and every real processor declines them, which is the whole reason a fixed published
    /// list is used instead of generating Luhn-valid numbers that could belong to a real cardholder.
    /// </para>
    /// <para>
    /// The catalogue already checks its own entries when the type is initialised, so these tests would fail
    /// as a type-initialisation error rather than an assertion if a number were mistyped. They are here so
    /// the failure names what is wrong, and so the check cannot be removed unnoticed.
    /// </para>
    /// </remarks>
    public class TestCardCatalogTests
    {
        /// <summary>The check digit example given in the Luhn algorithm's own published description.</summary>
        private const string KnownValidNumber = "79927398713";

        [Fact]
        public void Every_published_number_passes_the_luhn_check()
        {
            Assert.NotEmpty(TestCardCatalog.All);

            Assert.All(
                TestCardCatalog.All,
                card => Assert.True(
                    card.LuhnValid,
                    $"The {card.DisplayName} test number of {card.Digits} digits fails the Luhn check."));
        }

        [Fact]
        public void Every_published_number_is_a_plausible_card_number()
        {
            Assert.All(
                TestCardCatalog.All,
                card =>
                {
                    Assert.True(
                        card.Number.All(char.IsAsciiDigit),
                        $"The {card.DisplayName} test number contains something other than digits.");
                    Assert.InRange(card.Digits, 12, 19);
                    Assert.Equal(card.Number.Length, card.Digits);
                    Assert.Contains(card.SecurityCodeDigits, new[] { 3, 4 });
                    Assert.False(
                        string.IsNullOrWhiteSpace(card.Description),
                        $"The {card.DisplayName} test number has no description.");
                });
        }

        [Fact]
        public void No_number_appears_twice()
        {
            var numbers = TestCardCatalog.All.Select(card => card.Number).ToArray();

            Assert.Equal(numbers.Length, numbers.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public void The_listing_is_ordered_by_brand_so_it_is_stable()
        {
            var brands = TestCardCatalog.All.Select(card => card.Brand).ToArray();
            var sorted = brands.OrderBy(brand => brand, StringComparer.OrdinalIgnoreCase).ToArray();

            Assert.Equal(sorted, brands);
        }

        [Fact]
        public void The_brand_list_names_each_brand_once()
        {
            var brands = TestCardCatalog.Brands.ToArray();
            var distinct = TestCardCatalog.All
                .Select(card => card.Brand)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Assert.NotEmpty(brands);
            Assert.Equal(brands.Length, brands.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            Assert.Equal(distinct, brands);
        }

        [Fact]
        public void Every_brand_resolves_to_at_least_one_number()
        {
            Assert.All(
                TestCardCatalog.Brands,
                brand => Assert.NotEmpty(TestCardCatalog.Resolve(brand)));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void An_omitted_brand_returns_every_number(string? brand)
        {
            Assert.Equal(TestCardCatalog.All.Count, TestCardCatalog.Resolve(brand).Count);
        }

        [Theory]
        [InlineData("amex")]
        [InlineData("AMEX")]
        [InlineData("AmEx")]
        [InlineData("  amex  ")]
        public void A_brand_resolves_however_the_caller_wrote_it(string brand)
        {
            var cards = TestCardCatalog.Resolve(brand);

            Assert.NotEmpty(cards);
            Assert.All(cards, card => Assert.Equal("amex", card.Brand));
        }

        [Fact]
        public void American_express_numbers_carry_the_length_and_security_code_that_network_uses()
        {
            // The case a checkout form that hard-codes 16 digits and a three digit code gets wrong.
            Assert.All(
                TestCardCatalog.Resolve("amex"),
                card =>
                {
                    Assert.Equal(15, card.Digits);
                    Assert.Equal(4, card.SecurityCodeDigits);
                });
        }

        [Fact]
        public void The_catalogue_covers_more_than_one_card_length()
        {
            // A validator that assumes every card has 16 digits is the mistake this list exists to expose.
            var lengths = TestCardCatalog.All.Select(card => card.Digits).Distinct().ToArray();

            Assert.True(lengths.Length > 1, "Every published test number has the same length.");
        }

        [Fact]
        public void An_unknown_brand_is_refused_with_the_brands_that_do_work()
        {
            var failure = Assert.Throws<CryptographicRequestException>(
                () => TestCardCatalog.Resolve("notacard"));

            Assert.Contains("Unsupported card brand 'notacard'", failure.Message, StringComparison.Ordinal);

            Assert.All(
                TestCardCatalog.Brands,
                brand => Assert.Contains(brand, failure.Message, StringComparison.Ordinal));
        }

        [Fact]
        public void The_published_warning_says_these_are_not_real_and_not_secret()
        {
            Assert.Contains("published test numbers", TestCardCatalog.PublishedWarning, StringComparison.Ordinal);
            Assert.Contains("declined", TestCardCatalog.PublishedWarning, StringComparison.Ordinal);
            Assert.Contains("Never put a real card", TestCardCatalog.PublishedWarning, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(KnownValidNumber)]
        [InlineData("4111111111111111")]
        [InlineData("4111 1111 1111 1111")]
        [InlineData("4111-1111-1111-1111")]
        public void The_luhn_check_accepts_a_correct_number_however_it_is_spaced(string number)
        {
            Assert.True(TestCardCatalog.IsLuhnValid(number), "A correct number was rejected.");
        }

        [Theory]
        [InlineData("79927398710")]
        [InlineData("79927398714")]
        [InlineData("4111111111111112")]
        [InlineData("4111111111111121")]
        public void The_luhn_check_rejects_a_mistyped_digit(string number)
        {
            // Luhn's whole purpose: a single wrong or transposed digit does not pass.
            Assert.False(TestCardCatalog.IsLuhnValid(number), "A mistyped number was accepted.");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("4111111111111a11")]
        [InlineData("not a number")]
        [InlineData("0")]
        public void The_luhn_check_rejects_input_that_is_not_a_number(string? number)
        {
            Assert.False(TestCardCatalog.IsLuhnValid(number), "Something that is not a number was accepted.");
        }
    }
}
