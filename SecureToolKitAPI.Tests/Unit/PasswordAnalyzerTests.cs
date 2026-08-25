using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;
using SecureToolKitAPI.Cryptography.Recovery;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The password analyzer: that the entropy calculator is exact arithmetic, that the strength check
    /// prices structure it can see rather than trusting the alphabet, that it reports an upper bound and
    /// says so, and that neither path ever repeats the caller's password back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The passwords used here are literals written for the test. None is a real credential, and none is
    /// printed by an assertion: where a check involves the password itself it asserts over a boolean with
    /// a message that names the defect.
    /// </para>
    /// <para>
    /// Exact figures are asserted only where the arithmetic is exact and the value is far from a rounding
    /// boundary. Where the interesting property is which bound bit rather than the digit it produced, the
    /// assertion is a comparison against the figure a naive alphabet count would have given — that is the
    /// behaviour worth locking down, and it does not become brittle if a bound is later refined.
    /// </para>
    /// </remarks>
    public class PasswordAnalyzerTests
    {
        /// <summary>
        /// Sixteen characters over all four classes with no repeat, no step and no repeated block. Written
        /// for this test; not a credential.
        /// </summary>
        private const string Unpatterned = "Qz7#Kp2$Mw9%Rt4&";

        /// <summary>Sixteen lowercase characters with no repeat, step or repeated block.</summary>
        private const string LowercaseOnly = "qhznwbktrvmxdjpg";

        /// <summary>The shape almost every chosen password has: a word, a digit, a symbol.</summary>
        private const string HumanShape = "Password1!";

        /// <summary>A password containing nothing a description of it could plausibly also contain.</summary>
        private const string Traceable = "Wk4#Zx9$Jm2%Qr7&";

        private readonly PasswordAnalyzer _analyzer = new();

        [Fact]
        public void A_missing_password_is_refused_rather_than_scored_as_nothing()
        {
            var missing = Assert.Throws<CryptographicRequestException>(() => _analyzer.Analyze(null));
            var empty = Assert.Throws<CryptographicRequestException>(() => _analyzer.Analyze(string.Empty));

            Assert.Equal("A password is required.", missing.Message);
            Assert.Equal("A password is required.", empty.Message);
        }

        [Fact]
        public void A_password_longer_than_this_api_generates_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _analyzer.Analyze(new string('a', PasswordSpec.MaximumLength + 1)));

            Assert.Contains("at most 512 characters", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_password_at_the_length_limit_is_still_analyzed()
        {
            var result = _analyzer.Analyze(new string('a', PasswordSpec.MaximumLength));

            Assert.Equal(PasswordSpec.MaximumLength, result.Length);
        }

        [Fact]
        public void One_character_repeated_is_worth_only_that_character()
        {
            var result = _analyzer.Analyze(new string('a', 16));

            // The repetition bound: sixteen copies of one lowercase letter cost what naming the letter
            // costs, log2(26), and nothing more. A count of the alphabet would have said 75 bits.
            Assert.Equal(4.7d, result.EntropyBits);
            Assert.Equal("Very weak", result.Strength);
            Assert.Equal("lowercase (26 character alphabet)", result.Composition);
        }

        [Fact]
        public void A_run_of_consecutive_letters_costs_almost_nothing_per_step()
        {
            var result = _analyzer.Analyze("abcdefgh");

            // The alphabet bound with the step price: one letter at log2(26), then seven continuations at
            // log2(3) each. Counting the alphabet alone would have said 37.6 bits.
            Assert.Equal(15.8d, result.EntropyBits);
            Assert.Equal("Very weak", result.Strength);
        }

        [Fact]
        public void Sixteen_unpatterned_characters_keep_almost_all_of_their_alphabet()
        {
            var result = _analyzer.Analyze(Unpatterned);

            // Nothing here repeats, steps or recurs, so only the cost of describing where the classes
            // change is deducted: 103.4 bits against the 105.1 a bare alphabet count would give.
            Assert.Equal(103.4d, result.EntropyBits);
            Assert.Equal("Strong", result.Strength);
            Assert.Equal("lowercase, uppercase, digits, ASCII symbols (95 character alphabet)", result.Composition);
            Assert.Empty(result.Findings);
        }

        [Fact]
        public void Sixteen_unpatterned_lowercase_characters_are_priced_at_their_alphabet()
        {
            var result = _analyzer.Analyze(LowercaseOnly);

            // Sixteen characters over 26 symbols, with nothing to deduct.
            Assert.Equal(75.2d, result.EntropyBits);
            Assert.Equal("Strong", result.Strength);
            Assert.Equal("lowercase (26 character alphabet)", result.Composition);
        }

        [Fact]
        public void A_generated_password_is_never_scored_below_the_alphabet_it_was_drawn_from()
        {
            // The point of the bounds is to catch structure, not to punish randomness. A value this API
            // actually generates has none of the structure they look for, so none of them may bite.
            var alphabet = 16 * Math.Log2(95);
            var result = _analyzer.Analyze(Unpatterned);

            Assert.InRange(result.EntropyBits, alphabet - 2d, alphabet);
        }

        [Fact]
        public void The_usual_human_shape_is_priced_below_its_alphabet()
        {
            var result = _analyzer.Analyze(HumanShape);

            // Four classes over ten characters looks like 65.7 bits if you only count the alphabet. Naming
            // where the classes change, and that one character repeats the one before it, costs less.
            Assert.True(
                result.EntropyBits < 10 * Math.Log2(95),
                "A password with an obvious class shape was priced at its full alphabet, so no bound bit.");
            Assert.Equal(PasswordStrength.Describe(result.EntropyBits), result.Strength);
        }

        [Fact]
        public void Only_one_character_class_is_reported_as_a_finding()
        {
            var single = _analyzer.Analyze(LowercaseOnly);
            var several = _analyzer.Analyze(Unpatterned);

            Assert.Contains(
                single.Findings,
                finding => finding.Contains("Only one character class", StringComparison.Ordinal));
            Assert.DoesNotContain(
                several.Findings,
                finding => finding.Contains("Only one character class", StringComparison.Ordinal));
        }

        [Fact]
        public void A_repeated_block_is_reported_as_a_finding()
        {
            var result = _analyzer.Analyze("Ab3$Ab3$Ab3$");

            Assert.Contains(
                result.Findings,
                finding => finding.Contains("4-character block repeated 3 times", StringComparison.Ordinal));
        }

        [Fact]
        public void Characters_that_continue_the_one_before_them_are_reported_as_a_finding()
        {
            var result = _analyzer.Analyze("abcdefgh");

            Assert.Contains(
                result.Findings,
                finding => finding.Contains(
                    "7 of the 8 characters repeat the one before them",
                    StringComparison.Ordinal));
        }

        [Fact]
        public void Being_shorter_than_the_recommended_length_is_reported_as_a_finding()
        {
            var shorter = _analyzer.Analyze("Kp7#Vz2$");
            var longer = _analyzer.Analyze(Unpatterned);

            Assert.Contains(
                shorter.Findings,
                finding => finding.Contains("shorter than the 12", StringComparison.Ordinal));
            Assert.DoesNotContain(
                longer.Findings,
                finding => finding.Contains("shorter than the 12", StringComparison.Ordinal));
        }

        [Fact]
        public void A_password_with_nothing_to_report_gets_no_findings_and_no_advisory()
        {
            var result = _analyzer.Analyze(Unpatterned);

            Assert.Empty(result.Findings);
            Assert.Equal(3, result.Warnings.Count);
            Assert.DoesNotContain(
                result.Warnings,
                warning => warning.Contains("priced generously", StringComparison.Ordinal));
            Assert.DoesNotContain(
                result.Warnings,
                warning => warning.Contains("below the 60 bits", StringComparison.Ordinal));
        }

        [Fact]
        public void The_assessment_always_says_the_figure_is_an_upper_bound_and_what_it_cannot_see()
        {
            var result = _analyzer.Analyze(Unpatterned);

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("upper bound inferred from the characters", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("appeared in a breach", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("not logged, stored or echoed", StringComparison.Ordinal));
        }

        [Fact]
        public void A_weak_password_is_told_it_is_weak_and_that_the_findings_flatter_it()
        {
            var result = _analyzer.Analyze("abcdefgh");

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("below the 60 bits", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("priced generously", StringComparison.Ordinal));
        }

        [Fact]
        public void Nothing_in_the_assessment_repeats_any_part_of_the_password()
        {
            var result = _analyzer.Analyze(Traceable);

            var reported = new List<string> { result.Composition, result.Strength };
            reported.AddRange(result.Findings);
            reported.AddRange(result.Warnings);

            for (var start = 0; start + 3 <= Traceable.Length; start++)
            {
                var fragment = Traceable.Substring(start, 3);

                Assert.False(
                    reported.Any(text => text.Contains(fragment, StringComparison.Ordinal)),
                    "The assessment quoted a three character run of the password it was given.");
            }
        }

        [Theory]
        [InlineData(Unpatterned)]
        [InlineData(LowercaseOnly)]
        [InlineData(HumanShape)]
        [InlineData("abcdefgh")]
        [InlineData("aaaaaaaaaaaaaaaa")]
        public void The_guess_count_is_the_logarithm_of_the_reported_bits(string password)
        {
            var result = _analyzer.Analyze(password);

            // Reported as a base ten logarithm because the count itself overflows every numeric type at
            // any real strength, so the two figures have to stay consistent with each other. The tolerance
            // covers both figures being rounded to one decimal place independently.
            var expected = result.EntropyBits * Math.Log10(2);

            Assert.InRange(result.GuessesLog10, expected - 0.1d, expected + 0.1d);
        }

        [Fact]
        public void The_default_entropy_calculation_describes_sixteen_characters_over_every_set()
        {
            var result = _analyzer.Estimate(new EntropySpec());

            Assert.Equal(16, result.Count);
            Assert.Equal(84, result.AlphabetSize);
            Assert.Equal(6.4d, result.EntropyBitsPerCharacter);
            Assert.Equal(102.3d, result.EntropyBits);
            Assert.Equal("Strong", result.Strength);
            Assert.Equal("lowercase, uppercase, digits, symbols (84 character alphabet)", result.Composition);
            Assert.Equal(30.8d, result.GuessesLog10);
        }

        [Fact]
        public void Excluding_the_ambiguous_characters_shrinks_the_alphabet_and_says_so()
        {
            var result = _analyzer.Estimate(new EntropySpec { ExcludeAmbiguous = true });

            Assert.Equal(73, result.AlphabetSize);
            Assert.Equal(6.2d, result.EntropyBitsPerCharacter);
            Assert.Equal(99d, result.EntropyBits);
            Assert.Equal(
                "lowercase, uppercase, digits, symbols (73 character alphabet, ambiguous characters excluded)",
                result.Composition);
        }

        [Fact]
        public void A_four_digit_pin_is_calculated_as_the_thirteen_bits_it_is()
        {
            var result = _analyzer.Estimate(
                new EntropySpec { Count = 4, Characters = PasswordCharacters.Digits });

            Assert.Equal(10, result.AlphabetSize);
            Assert.Equal(3.3d, result.EntropyBitsPerCharacter);
            Assert.Equal(13.3d, result.EntropyBits);
            Assert.Equal("Very weak", result.Strength);
            Assert.Equal("digits (10 character alphabet)", result.Composition);
        }

        [Fact]
        public void An_alphabet_given_by_size_alone_covers_a_scheme_this_api_does_not_generate()
        {
            // Six words from a 7776 word list: the alphabet is not a character set at all, which is why
            // naming it by size has to be supported.
            var result = _analyzer.Estimate(new EntropySpec { Count = 6, AlphabetSize = 7776 });

            Assert.Equal(7776, result.AlphabetSize);
            Assert.Equal(12.9d, result.EntropyBitsPerCharacter);
            Assert.Equal(77.5d, result.EntropyBits);
            Assert.Equal("Strong", result.Strength);
            Assert.Equal("7776 character alphabet", result.Composition);
        }

        [Fact]
        public void A_binary_alphabet_is_one_bit_per_character()
        {
            var result = _analyzer.Estimate(new EntropySpec { Count = 128, AlphabetSize = 2 });

            Assert.Equal(1d, result.EntropyBitsPerCharacter);
            Assert.Equal(128d, result.EntropyBits);
            Assert.Equal("Very strong", result.Strength);
            Assert.Equal(38.5d, result.GuessesLog10);
        }

        [Fact]
        public void A_calculation_says_what_it_assumes_and_gives_no_crack_time()
        {
            var result = _analyzer.Estimate(new EntropySpec());

            Assert.Equal(2, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("independently and uniformly at random", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("No crack time is given", StringComparison.Ordinal));
        }

        [Fact]
        public void A_calculation_below_the_advisory_threshold_says_how_to_fix_it()
        {
            var result = _analyzer.Estimate(new EntropySpec { Count = 8 });

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Add characters or use a larger alphabet", StringComparison.Ordinal));
        }

        [Fact]
        public void Describing_the_alphabet_twice_is_refused_rather_than_guessed_at()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _analyzer.Estimate(
                    new EntropySpec { Characters = PasswordCharacters.Digits, AlphabetSize = 10 }));

            Assert.Equal("Supply either character sets or an alphabet size, not both.", exception.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(4097)]
        public void A_character_count_outside_the_supported_range_is_refused(int count)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _analyzer.Estimate(new EntropySpec { Count = count }));

            Assert.Contains("between 1 and 4096", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(1_048_577)]
        public void An_alphabet_size_outside_the_supported_range_is_refused(int alphabetSize)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _analyzer.Estimate(new EntropySpec { AlphabetSize = alphabetSize }));

            Assert.Contains("between 2 and 1048576", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_empty_selection_of_character_sets_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _analyzer.Estimate(new EntropySpec { Characters = PasswordCharacters.None }));

            Assert.Contains("At least one character set must be selected", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Calculating_without_options_is_rejected_rather_than_silently_defaulted()
        {
            Assert.Throws<ArgumentNullException>(() => _analyzer.Estimate(null!));
        }
    }
}
