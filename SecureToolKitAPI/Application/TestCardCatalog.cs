using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Application
{
    /// <summary>
    /// One published card number reserved for testing, together with what a form validator will expect of
    /// it.
    /// </summary>
    /// <remarks>
    /// This is not a credential and not secret. Every number here is published by the card networks and by
    /// payment gateways specifically so that checkout forms, validators and fixtures can be exercised, and
    /// every one of them is declined by a real payment processor.
    /// </remarks>
    public sealed record TestCard
    {
        /// <summary>Identifier used in the request and in the listing, for example <c>visa</c>.</summary>
        public required string Brand { get; init; }

        /// <summary>The network's name, as it is usually written.</summary>
        public required string DisplayName { get; init; }

        /// <summary>The published test number.</summary>
        public required string Number { get; init; }

        /// <summary>Digits the number contains, which is what a length check should accept.</summary>
        public int Digits => Number.Length;

        /// <summary>Digits in the security code this network uses: four for American Express, otherwise three.</summary>
        public required int SecurityCodeDigits { get; init; }

        /// <summary>
        /// Whether the number satisfies the Luhn check, computed here rather than asserted, so the listing
        /// cannot claim something the number does not do.
        /// </summary>
        public bool LuhnValid => TestCardCatalog.IsLuhnValid(Number);

        /// <summary>What this particular number is useful for testing.</summary>
        public required string Description { get; init; }
    }

    /// <summary>
    /// The published card numbers reserved for testing, with the Luhn check used to validate them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These numbers are public. They are printed in the card networks' and payment gateways' own
    /// documentation for exactly this purpose, they are not issued to anybody, and a real processor
    /// declines them. Nothing here is a secret, so nothing here is generated, and nothing here needs
    /// protecting.
    /// </para>
    /// <para>
    /// They are a fixed list rather than randomly generated on purpose. Producing a random Luhn-valid
    /// number under a real issuer prefix would be trivial, and it could land on a number that belongs to an
    /// actual cardholder — a number this API would then present as safe to use. A published, reserved list
    /// cannot do that.
    /// </para>
    /// <para>
    /// Cards are data, not behaviour, and none of this is cryptography, which is why the catalogue lives in
    /// the application layer beside <see cref="AiKeyProviderCatalog"/> rather than in the cryptography
    /// layer. Adding a number is a single entry below.
    /// </para>
    /// </remarks>
    public static class TestCardCatalog
    {
        /// <summary>The advisory attached to every response that lists these numbers.</summary>
        public const string PublishedWarning =
            "These are published test numbers reserved by the card networks. They are not issued to anyone, "
            + "they are declined by every real processor, and they are not secret. Never put a real card "
            + "number into a test fixture, and never send one to this API.";

        private static readonly TestCard[] Cards =
        [
            .. new TestCard[]
            {
                new()
                {
                    Brand = "visa",
                    DisplayName = "Visa",
                    Number = "4111111111111111",
                    SecurityCodeDigits = 3,
                    Description = "The 16 digit Visa number, and the most widely recognised test card there is."
                },
                new()
                {
                    Brand = "visa",
                    DisplayName = "Visa",
                    Number = "4222222222222",
                    SecurityCodeDigits = 3,
                    Description =
                        "A 13 digit Visa number, for checking that a form accepts the shorter legacy length "
                        + "rather than assuming every card has 16 digits."
                },
                new()
                {
                    Brand = "mastercard",
                    DisplayName = "Mastercard",
                    Number = "5555555555554444",
                    SecurityCodeDigits = 3,
                    Description = "The 16 digit Mastercard number in the 51-55 range."
                },
                new()
                {
                    Brand = "mastercard",
                    DisplayName = "Mastercard",
                    Number = "5105105105105100",
                    SecurityCodeDigits = 3,
                    Description = "A second 51-55 Mastercard number, for testing more than one card on an account."
                },
                new()
                {
                    Brand = "mastercard",
                    DisplayName = "Mastercard",
                    Number = "2223003122003222",
                    SecurityCodeDigits = 3,
                    Description =
                        "A Mastercard number in the 2221-2720 range. Worth testing separately: a validator "
                        + "written before that range was introduced rejects it as an unknown network."
                },
                new()
                {
                    Brand = "amex",
                    DisplayName = "American Express",
                    Number = "378282246310005",
                    SecurityCodeDigits = 4,
                    Description =
                        "A 15 digit American Express number with a four digit security code, which is where "
                        + "a form that hard-codes 16 digits and three digits fails."
                },
                new()
                {
                    Brand = "amex",
                    DisplayName = "American Express",
                    Number = "371449635398431",
                    SecurityCodeDigits = 4,
                    Description = "A second 15 digit American Express number."
                },
                new()
                {
                    Brand = "discover",
                    DisplayName = "Discover",
                    Number = "6011111111111117",
                    SecurityCodeDigits = 3,
                    Description = "The 16 digit Discover number."
                },
                new()
                {
                    Brand = "discover",
                    DisplayName = "Discover",
                    Number = "6011000990139424",
                    SecurityCodeDigits = 3,
                    Description = "A second 16 digit Discover number."
                },
                new()
                {
                    Brand = "jcb",
                    DisplayName = "JCB",
                    Number = "3530111333300000",
                    SecurityCodeDigits = 3,
                    Description = "The 16 digit JCB number."
                },
                new()
                {
                    Brand = "jcb",
                    DisplayName = "JCB",
                    Number = "3566002020360505",
                    SecurityCodeDigits = 3,
                    Description = "A second 16 digit JCB number."
                },
                new()
                {
                    Brand = "diners",
                    DisplayName = "Diners Club",
                    Number = "30569309025904",
                    SecurityCodeDigits = 3,
                    Description =
                        "A 14 digit Diners Club number, the other length a validator that assumes 16 digits "
                        + "gets wrong."
                },
                new()
                {
                    Brand = "diners",
                    DisplayName = "Diners Club",
                    Number = "38520000023237",
                    SecurityCodeDigits = 3,
                    Description = "A second 14 digit Diners Club number."
                },
                new()
                {
                    Brand = "unionpay",
                    DisplayName = "UnionPay",
                    Number = "6200000000000005",
                    SecurityCodeDigits = 3,
                    Description = "A 16 digit UnionPay number."
                },
                new()
                {
                    Brand = "maestro",
                    DisplayName = "Maestro",
                    Number = "6759649826438453",
                    SecurityCodeDigits = 3,
                    Description = "A 16 digit Maestro number."
                }
            }.OrderBy(card => card.Brand, StringComparer.OrdinalIgnoreCase)
        ];

        private static readonly Dictionary<string, TestCard[]> ByBrand = BuildIndex();

        /// <summary>All test numbers, ordered by brand so the listing is stable.</summary>
        public static IReadOnlyList<TestCard> All => Cards;

        /// <summary>The brands in the catalogue, ordered as in <see cref="All"/>.</summary>
        public static IReadOnlyList<string> Brands =>
            [.. Cards.Select(card => card.Brand).Distinct(StringComparer.OrdinalIgnoreCase)];

        /// <summary>
        /// Resolves the numbers for one brand, ignoring case and surrounding whitespace. An omitted brand
        /// returns every number.
        /// </summary>
        /// <param name="brand">Brand name supplied by the caller, or <c>null</c> for all of them.</param>
        /// <returns>The matching numbers.</returns>
        /// <exception cref="CryptographicRequestException">The brand is not in the catalogue.</exception>
        /// <remarks>
        /// The failure message lists the supported brands, matching how
        /// <see cref="AiKeyProviderCatalog.Resolve"/> reports an unknown name.
        /// </remarks>
        public static IReadOnlyList<TestCard> Resolve(string? brand)
        {
            if (string.IsNullOrWhiteSpace(brand))
            {
                return Cards;
            }

            if (ByBrand.TryGetValue(brand.Trim(), out var cards))
            {
                return cards;
            }

            throw new CryptographicRequestException(
                $"Unsupported card brand '{brand.Trim()}'. Supported brands: {string.Join(", ", Brands)}.");
        }

        /// <summary>
        /// Applies the Luhn check digit algorithm, which is the check a card form runs before it sends
        /// anything anywhere.
        /// </summary>
        /// <param name="number">The digits to check. Spaces and hyphens are ignored.</param>
        /// <returns><c>true</c> when the number satisfies the check.</returns>
        /// <remarks>
        /// Luhn is a transcription check, not a security control: it catches a mistyped digit and nothing
        /// else. Anyone can compute a number that passes it, which is precisely why the numbers in this
        /// catalogue are the published reserved ones rather than generated.
        /// </remarks>
        internal static bool IsLuhnValid(string? number)
        {
            if (string.IsNullOrWhiteSpace(number))
            {
                return false;
            }

            var sum = 0;
            var digits = 0;
            var doubling = false;

            // Right to left, because whether a digit is doubled depends on its distance from the check
            // digit rather than from the start.
            for (var index = number.Length - 1; index >= 0; index--)
            {
                var character = number[index];

                if (character is ' ' or '-')
                {
                    continue;
                }

                if (!char.IsAsciiDigit(character))
                {
                    return false;
                }

                var digit = character - '0';
                digits++;

                if (doubling)
                {
                    digit *= 2;

                    if (digit > 9)
                    {
                        digit -= 9;
                    }
                }

                sum += digit;
                doubling = !doubling;
            }

            return digits > 1 && sum % 10 == 0;
        }

        /// <summary>
        /// Groups the numbers by brand, and proves at type-initialisation time that every entry is a
        /// plausible card number that actually passes the Luhn check — a mistyped digit then fails
        /// immediately rather than being handed out as a working test number.
        /// </summary>
        private static Dictionary<string, TestCard[]> BuildIndex()
        {
            foreach (var card in Cards)
            {
                if (!IsLuhnValid(card.Number))
                {
                    throw new InvalidOperationException(
                        $"The {card.DisplayName} test number of {card.Digits} digits fails the Luhn check, "
                        + "so it has been mistyped.");
                }

                if (card.Digits is < 12 or > 19)
                {
                    throw new InvalidOperationException(
                        $"A {card.DisplayName} test number has {card.Digits} digits, which is not a card "
                        + "number length.");
                }
            }

            return Cards
                .GroupBy(card => card.Brand, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        }
    }
}
