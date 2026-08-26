using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;
using SecureToolKitAPI.Cryptography.PasswordGeneration;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The password generator itself: that it honours the options it is given, refuses the options it
    /// cannot satisfy, and reports figures that match what it actually did.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These tests do generate secrets, so no assertion is allowed to print one. Anything that inspects a
    /// generated value is asserted through <see cref="Assert.True(bool, string)"/> with a message that
    /// names the problem instead of showing the value, and nothing here uses a fixed or production secret.
    /// </para>
    /// <para>
    /// Randomness is checked by repeating a generation and asserting a property that must hold every time,
    /// rather than by seeding: the generator draws from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> and cannot be made deterministic,
    /// which is the point.
    /// </para>
    /// </remarks>
    public class PasswordGeneratorTests
    {
        /// <summary>
        /// How many times a property is re-checked. Enough that a generator ignoring a character set
        /// would fail reliably, small enough to keep the suite fast.
        /// </summary>
        private const int Iterations = 50;

        private readonly PasswordGenerator _generator = new();

        [Fact]
        public void The_default_options_produce_a_strong_sixteen_character_password()
        {
            var result = _generator.Generate(new PasswordSpec());

            Assert.Equal(16, result.Length);
            Assert.Equal(16, result.Value.Length);
            Assert.Equal("lowercase, uppercase, digits, symbols (84 character alphabet)", result.Composition);
            Assert.Equal("Strong", result.Strength);
            Assert.Empty(result.Warnings);

            // One character from each of the four sets, then twelve from the full 84 character alphabet.
            Assert.Equal(93.9, result.EntropyBits);
        }

        [Theory]
        [InlineData(PasswordCharacters.All, false, 16)]
        [InlineData(PasswordCharacters.All, true, 32)]
        [InlineData(PasswordCharacters.Alphanumeric, false, 20)]
        [InlineData(PasswordCharacters.Alphanumeric, true, 12)]
        [InlineData(PasswordCharacters.LettersOnly, false, 16)]
        [InlineData(PasswordCharacters.Digits, false, 8)]
        [InlineData(PasswordCharacters.Symbols, false, 24)]
        [InlineData(PasswordCharacters.All, false, PasswordSpec.MinimumLength)]
        [InlineData(PasswordCharacters.All, false, PasswordSpec.MaximumLength)]
        public void A_password_has_the_requested_length_and_uses_only_the_requested_alphabet(
            PasswordCharacters characters,
            bool excludeAmbiguous,
            int length)
        {
            var alphabet = PasswordCharsets.For(characters, excludeAmbiguous);

            var result = _generator.Generate(new PasswordSpec
            {
                Length = length,
                Characters = characters,
                ExcludeAmbiguous = excludeAmbiguous
            });

            Assert.Equal(length, result.Length);
            Assert.Equal(length, result.Value.Length);

            Assert.True(
                result.Value.All(character => alphabet.Contains(character, StringComparison.Ordinal)),
                "The password contained a character from outside the selected alphabet.");
        }

        [Fact]
        public void Requiring_every_set_puts_at_least_one_character_from_each_into_every_password()
        {
            // The shortest length that can satisfy all four sets, so a generator that skipped one has
            // nowhere to hide.
            var spec = new PasswordSpec { Length = 4, Characters = PasswordCharacters.All };

            for (var attempt = 0; attempt < Iterations; attempt++)
            {
                var value = _generator.Generate(spec).Value;

                foreach (var set in PasswordCharsets.SelectedSets(PasswordCharacters.All))
                {
                    var characters = PasswordCharsets.Set(set, excludeAmbiguous: false);

                    Assert.True(
                        value.Any(character => characters.Contains(character, StringComparison.Ordinal)),
                        "A password generated with every set required was missing one of them.");
                }
            }
        }

        [Fact]
        public void Not_requiring_every_set_reports_the_full_alphabet_for_every_character()
        {
            var result = _generator.Generate(new PasswordSpec
            {
                Length = 16,
                Characters = PasswordCharacters.All,
                RequireEachSet = false
            });

            // Nothing is drawn from a smaller set, so the figure is the unconstrained maximum.
            Assert.Equal(102.3, result.EntropyBits);
        }

        [Fact]
        public void Requiring_every_set_never_reports_more_than_the_unconstrained_maximum()
        {
            var constrained = _generator.Generate(new PasswordSpec { Length = 16 });

            var unconstrained = _generator.Generate(new PasswordSpec
            {
                Length = 16,
                RequireEachSet = false
            });

            // Guaranteed positions are drawn from a smaller set and the final shuffle is not counted, so
            // the reported figure has to be a lower bound rather than an optimistic one.
            Assert.True(
                constrained.EntropyBits < unconstrained.EntropyBits,
                "Requiring one character per set reported at least as much entropy as drawing freely.");
        }

        [Fact]
        public void Excluding_ambiguous_characters_keeps_them_out_of_every_password()
        {
            var spec = new PasswordSpec { Length = 32, ExcludeAmbiguous = true };

            for (var attempt = 0; attempt < Iterations; attempt++)
            {
                var value = _generator.Generate(spec).Value;

                Assert.True(
                    value.All(character => !PasswordCharsets.Ambiguous.Contains(character, StringComparison.Ordinal)),
                    "A password generated without ambiguous characters contained one.");
            }

            Assert.Contains("ambiguous characters excluded", _generator.Generate(spec).Composition, StringComparison.Ordinal);
        }

        [Fact]
        public void Independent_calls_do_not_repeat()
        {
            var spec = new PasswordSpec { Length = 20 };

            var generated = Enumerable.Range(0, Iterations)
                .Select(_ => _generator.Generate(spec).Value)
                .ToArray();

            // A 20 character password from an 84 character alphabet repeating within 50 draws would mean
            // the generator is not random. Only the counts are asserted, so no value reaches the log.
            Assert.Equal(Iterations, generated.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public void A_digits_only_password_is_returned_with_a_warning_rather_than_silently()
        {
            var result = _generator.Generate(new PasswordSpec
            {
                Length = 12,
                Characters = PasswordCharacters.Digits
            });

            Assert.Equal(39.9, result.EntropyBits);
            Assert.Contains(result.Warnings, warning => warning.Contains("digits alone", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void A_password_weaker_than_the_advisory_threshold_says_so()
        {
            var result = _generator.Generate(new PasswordSpec { Length = 6 });

            Assert.True(
                result.EntropyBits < 60d,
                "The six character password was expected to fall below the advisory threshold.");

            Assert.Contains(result.Warnings, warning => warning.Contains("bits of entropy", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(PasswordSpec.MinimumLength - 1)]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(PasswordSpec.MaximumLength + 1)]
        public void A_length_outside_the_supported_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.Generate(new PasswordSpec { Length = length }));

            Assert.Contains("between 4 and 512", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Selecting_no_character_set_is_refused()
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.Generate(new PasswordSpec { Characters = PasswordCharacters.None }));
        }

        [Fact]
        public void Excluding_ambiguous_characters_from_a_digits_only_password_still_leaves_enough_to_generate_from()
        {
            // Five of the ten digits are ambiguous. The remaining five are still enough, so this must
            // succeed rather than fail on an alphabet that is too small.
            var result = _generator.Generate(new PasswordSpec
            {
                Length = 8,
                Characters = PasswordCharacters.Digits,
                ExcludeAmbiguous = true
            });

            Assert.Equal(8, result.Length);
            Assert.True(
                result.Value.All(character => "34679".Contains(character, StringComparison.Ordinal)),
                "An unambiguous digit password contained a digit that is easily confused with a letter.");
        }

        [Fact]
        public void Every_generator_refuses_a_missing_options_object()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.Generate(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateBulk(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GeneratePassphrase(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GeneratePronounceable(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GeneratePin(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateUsername(null!));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(10)]
        [InlineData(BulkPasswordSpec.MaximumCount)]
        public void Bulk_generation_returns_the_requested_number_of_independent_passwords(int count)
        {
            var generated = _generator.GenerateBulk(new BulkPasswordSpec
            {
                Count = count,
                Password = new PasswordSpec { Length = 20 }
            });

            Assert.Equal(count, generated.Count);
            Assert.All(generated, password => Assert.Equal(20, password.Length));

            // Independently generated, so no two share a value and none is derived from another.
            Assert.Equal(count, generated.Select(password => password.Value).Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public void Bulk_generation_applies_the_shared_options_to_every_password()
        {
            var alphabet = PasswordCharsets.For(PasswordCharacters.Alphanumeric, excludeAmbiguous: true);

            var generated = _generator.GenerateBulk(new BulkPasswordSpec
            {
                Count = 5,
                Password = new PasswordSpec
                {
                    Length = 12,
                    Characters = PasswordCharacters.Alphanumeric,
                    ExcludeAmbiguous = true
                }
            });

            Assert.All(generated, password => Assert.True(
                password.Value.Length == 12
                && password.Value.All(character => alphabet.Contains(character, StringComparison.Ordinal)),
                "A password in the batch did not use the shared options."));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(BulkPasswordSpec.MaximumCount + 1)]
        public void A_bulk_count_outside_the_supported_range_is_refused(int count)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateBulk(new BulkPasswordSpec { Count = count }));

            Assert.Contains("between 1 and 100", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_bulk_request_with_invalid_password_options_is_refused_before_anything_is_generated()
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateBulk(new BulkPasswordSpec
                {
                    Count = 5,
                    Password = new PasswordSpec { Length = 2 }
                }));
        }

        [Theory]
        [InlineData(PassphraseSpec.MinimumWords)]
        [InlineData(6)]
        [InlineData(PassphraseSpec.MaximumWords)]
        public void A_passphrase_is_built_from_the_requested_number_of_words_from_the_list(int words)
        {
            var result = _generator.GeneratePassphrase(new PassphraseSpec { Words = words, Separator = "-" });

            var parts = result.Value.Split('-');

            Assert.Equal(words, parts.Length);
            Assert.True(
                parts.All(part => Wordlist.Words.Contains(part, StringComparer.Ordinal)),
                "A passphrase contained something that is not a word from the list.");

            Assert.Equal(Math.Round(words * Math.Log2(Wordlist.Count), 1), result.EntropyBits);
            Assert.Contains($"{words} words", result.Composition, StringComparison.Ordinal);
        }

        [Fact]
        public void The_default_passphrase_is_strong_enough_to_rely_on()
        {
            var result = _generator.GeneratePassphrase(new PassphraseSpec());

            Assert.True(
                result.EntropyBits >= 60d,
                "The default six word passphrase fell below the threshold worth relying on.");

            Assert.Equal("Strong", result.Strength);
            Assert.Empty(result.Warnings);
        }

        [Fact]
        public void A_capitalised_passphrase_starts_every_word_with_an_uppercase_letter()
        {
            var result = _generator.GeneratePassphrase(new PassphraseSpec
            {
                Words = 5,
                Separator = "-",
                Capitalize = true
            });

            Assert.True(
                result.Value.Split('-').All(part => char.IsAsciiLetterUpper(part[0])),
                "A word in the capitalised passphrase did not start with an uppercase letter.");
        }

        [Fact]
        public void A_passphrase_can_carry_the_digit_and_symbol_a_policy_demands()
        {
            var plain = _generator.GeneratePassphrase(new PassphraseSpec { Words = 4 });

            var decorated = _generator.GeneratePassphrase(new PassphraseSpec
            {
                Words = 4,
                IncludeNumber = true,
                IncludeSymbol = true
            });

            // The symbol is appended last, the digit before it.
            Assert.True(
                PasswordCharsets.Symbols.Contains(decorated.Value[^1], StringComparison.Ordinal),
                "The passphrase did not end with the requested symbol.");

            Assert.True(
                char.IsAsciiDigit(decorated.Value[^2]),
                "The passphrase did not contain the requested digit before its symbol.");

            Assert.Contains("one digit", decorated.Composition, StringComparison.Ordinal);
            Assert.Contains("one symbol", decorated.Composition, StringComparison.Ordinal);
            Assert.True(
                decorated.EntropyBits > plain.EntropyBits,
                "Adding a digit and a symbol did not increase the reported entropy.");
        }

        [Fact]
        public void An_empty_passphrase_separator_runs_the_words_together()
        {
            var result = _generator.GeneratePassphrase(new PassphraseSpec { Words = 4, Separator = string.Empty });

            Assert.True(
                result.Value.All(char.IsAsciiLetterLower),
                "A passphrase with no separator and no decoration contained something other than lowercase letters.");
        }

        [Theory]
        [InlineData(PassphraseSpec.MinimumWords - 1)]
        [InlineData(0)]
        [InlineData(PassphraseSpec.MaximumWords + 1)]
        public void A_passphrase_word_count_outside_the_supported_range_is_refused(int words)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GeneratePassphrase(new PassphraseSpec { Words = words }));

            Assert.Contains("between 3 and 24", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(" ")]
        [InlineData("\t")]
        [InlineData("-----")]
        public void A_passphrase_separator_that_would_break_the_value_is_refused(string separator)
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GeneratePassphrase(new PassphraseSpec { Separator = separator }));
        }

        [Theory]
        [InlineData(PronounceableSpec.MinimumSyllables)]
        [InlineData(6)]
        [InlineData(PronounceableSpec.MaximumSyllables)]
        public void A_pronounceable_value_is_letters_only_and_always_warns_about_its_strength(int syllables)
        {
            var result = _generator.GeneratePronounceable(new PronounceableSpec { Syllables = syllables });

            Assert.True(
                result.Value.All(char.IsAsciiLetterLower),
                "A pronounceable value contained something other than lowercase letters.");

            Assert.True(
                result.Value.Length >= syllables * 2,
                "A pronounceable value was shorter than one consonant and one vowel per syllable.");

            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("trades strength for readability", StringComparison.Ordinal));

            Assert.Contains($"{syllables} syllables", result.Composition, StringComparison.Ordinal);
        }

        [Fact]
        public void A_pronounceable_value_can_be_capitalised_and_take_a_digit()
        {
            var result = _generator.GeneratePronounceable(new PronounceableSpec
            {
                Syllables = 5,
                Capitalize = true,
                IncludeNumber = true
            });

            Assert.True(char.IsAsciiLetterUpper(result.Value[0]), "The pronounceable value was not capitalised.");
            Assert.True(char.IsAsciiDigit(result.Value[^1]), "The pronounceable value did not end with a digit.");
        }

        [Theory]
        [InlineData(PronounceableSpec.MinimumSyllables - 1)]
        [InlineData(PronounceableSpec.MaximumSyllables + 1)]
        public void A_syllable_count_outside_the_supported_range_is_refused(int syllables)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GeneratePronounceable(new PronounceableSpec { Syllables = syllables }));

            Assert.Contains("between 2 and 12", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(PinSpec.MinimumLength)]
        [InlineData(6)]
        [InlineData(PinSpec.MaximumLength)]
        public void A_pin_is_digits_only_and_always_warns_that_it_is_weak(int length)
        {
            var result = _generator.GeneratePin(new PinSpec { Length = length });

            Assert.Equal(length, result.Length);
            Assert.True(result.Value.All(char.IsAsciiDigit), "A PIN contained something other than a digit.");
            Assert.Equal(Math.Round(length * Math.Log2(10), 1), result.EntropyBits);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("weak by construction", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(PinSpec.MinimumLength - 1)]
        [InlineData(PinSpec.MaximumLength + 1)]
        public void A_pin_length_outside_the_supported_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GeneratePin(new PinSpec { Length = length }));

            Assert.Contains("between 3 and 16", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_username_is_reported_as_a_public_identifier_and_not_as_a_weak_secret()
        {
            var result = _generator.GenerateUsername(new UsernameSpec());

            // The low entropy advisory is deliberately suppressed here: a username is not a secret, so
            // telling the caller it is too weak to be one would be misleading.
            Assert.Single(result.Warnings);
            Assert.Contains("not a secret", result.Warnings[0], StringComparison.Ordinal);
            Assert.DoesNotContain(
                result.Warnings,
                warning => warning.Contains("bits of entropy", StringComparison.Ordinal));
        }

        [Fact]
        public void A_username_combines_words_from_the_list_with_a_two_digit_number()
        {
            var result = _generator.GenerateUsername(new UsernameSpec { Words = 2, Separator = ".", IncludeNumber = true });

            Assert.True(char.IsAsciiDigit(result.Value[^1]) && char.IsAsciiDigit(result.Value[^2]),
                "The username did not end with a two digit number.");

            var words = result.Value[..^2].Split('.');

            Assert.Equal(2, words.Length);
            Assert.True(
                words.All(word => Wordlist.Words.Contains(word, StringComparer.Ordinal)),
                "The username contained something that is not a word from the list.");
        }

        [Fact]
        public void A_username_can_be_generated_without_a_number()
        {
            var result = _generator.GenerateUsername(new UsernameSpec
            {
                Words = 1,
                IncludeNumber = false
            });

            Assert.True(
                Wordlist.Words.Contains(result.Value, StringComparer.Ordinal),
                "A single word username was not a word from the list.");
        }

        [Theory]
        [InlineData(UsernameSpec.MinimumWords - 1)]
        [InlineData(UsernameSpec.MaximumWords + 1)]
        public void A_username_word_count_outside_the_supported_range_is_refused(int words)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateUsername(new UsernameSpec { Words = words }));

            Assert.Contains("between 1 and 4", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("/")]
        [InlineData(" ")]
        [InlineData("@@@")]
        public void A_username_separator_that_is_not_safe_in_an_identifier_is_refused(string separator)
        {
            Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateUsername(new UsernameSpec { Separator = separator }));
        }

        [Fact]
        public void Every_generator_reports_a_strength_label_that_matches_its_own_figure()
        {
            foreach (var result in EveryKindOfValue())
            {
                Assert.Equal(PasswordStrength.Describe(result.EntropyBits), result.Strength);
                Assert.Equal(result.Value.Length, result.Length);
                Assert.True(result.EntropyBits > 0d, "A generated value was reported as carrying no entropy.");
            }
        }

        [Fact]
        public void No_generator_repeats_the_generated_value_in_the_text_it_returns()
        {
            foreach (var result in EveryKindOfValue())
            {
                // The composition and the warnings are the parts a caller may safely log, so neither may
                // contain the value itself. Failures name the field rather than showing the value.
                Assert.False(
                    result.Composition.Contains(result.Value, StringComparison.OrdinalIgnoreCase),
                    "The composition description contained the generated value.");

                Assert.False(
                    result.Warnings.Any(warning => warning.Contains(result.Value, StringComparison.OrdinalIgnoreCase)),
                    "A warning contained the generated value.");
            }
        }

        /// <summary>
        /// One result from every generator, so the cross-cutting properties are checked against all of
        /// them rather than only against a password.
        /// </summary>
        private IEnumerable<GeneratedPassword> EveryKindOfValue()
        {
            yield return _generator.Generate(new PasswordSpec());
            yield return _generator.Generate(new PasswordSpec { Length = 6, Characters = PasswordCharacters.Digits });
            yield return _generator.GeneratePassphrase(new PassphraseSpec());
            yield return _generator.GeneratePassphrase(new PassphraseSpec
            {
                Words = 4,
                Capitalize = true,
                IncludeNumber = true,
                IncludeSymbol = true
            });
            yield return _generator.GeneratePronounceable(new PronounceableSpec());
            yield return _generator.GeneratePin(new PinSpec());
            yield return _generator.GenerateUsername(new UsernameSpec());

            foreach (var password in _generator.GenerateBulk(new BulkPasswordSpec { Count = 3 }))
            {
                yield return password;
            }
        }
    }
}
