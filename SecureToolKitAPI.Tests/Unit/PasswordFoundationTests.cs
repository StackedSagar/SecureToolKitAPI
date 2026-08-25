using SecureToolKitAPI.Application;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Internal;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The shared pieces the password endpoints are built from: the alphabets, the entropy measurement,
    /// the word list, the option validation and the preset catalogue.
    /// </summary>
    /// <remarks>
    /// Nothing here generates a secret, so nothing here can leak one. These are the properties the
    /// generators rely on, checked once so a change to a charset or the word list cannot quietly
    /// invalidate the strength figures reported to callers.
    /// </remarks>
    public class PasswordFoundationTests
    {
        [Fact]
        public void The_alphabets_do_not_overlap_and_contain_no_repeated_character()
        {
            var all = PasswordCharsets.For(PasswordCharacters.All, excludeAmbiguous: false);

            Assert.Equal(84, all.Length);
            Assert.Equal(all.Length, all.Distinct().Count());
        }

        [Fact]
        public void The_symbol_set_excludes_the_characters_that_break_shells_and_data_formats()
        {
            const string troublesome = "\"'`\\;:,./|";

            Assert.DoesNotContain(
                PasswordCharsets.Symbols,
                symbol => troublesome.Contains(symbol, StringComparison.Ordinal));
        }

        [Fact]
        public void Excluding_ambiguous_characters_shrinks_every_affected_set_without_emptying_any()
        {
            var reduced = PasswordCharsets.For(PasswordCharacters.All, excludeAmbiguous: true);

            Assert.Equal(73, reduced.Length);
            Assert.DoesNotContain(reduced, character => PasswordCharsets.Ambiguous.Contains(character, StringComparison.Ordinal));

            foreach (var set in PasswordCharsets.SelectedSets(PasswordCharacters.All))
            {
                Assert.NotEmpty(PasswordCharsets.Set(set, excludeAmbiguous: true));
            }
        }

        [Theory]
        [InlineData(PasswordCharacters.All, 84)]
        [InlineData(PasswordCharacters.Alphanumeric, 62)]
        [InlineData(PasswordCharacters.LettersOnly, 52)]
        [InlineData(PasswordCharacters.Digits, 10)]
        [InlineData(PasswordCharacters.Symbols, 22)]
        [InlineData(PasswordCharacters.Lowercase | PasswordCharacters.Digits, 36)]
        public void A_selection_of_sets_produces_the_expected_alphabet_size(
            PasswordCharacters characters,
            int expectedSize)
        {
            Assert.Equal(expectedSize, PasswordCharsets.For(characters, excludeAmbiguous: false).Length);
        }

        [Fact]
        public void Selecting_no_set_is_refused_rather_than_producing_an_empty_alphabet()
        {
            Assert.Throws<CryptographicRequestException>(
                () => PasswordCharsets.For(PasswordCharacters.None, excludeAmbiguous: false));
        }

        [Fact]
        public void A_composition_describes_the_alphabet_without_containing_any_generated_value()
        {
            var description = PasswordCharsets.Describe(PasswordCharacters.All, excludeAmbiguous: true);

            Assert.Equal("lowercase, uppercase, digits, symbols (73 character alphabet, ambiguous characters excluded)", description);
            Assert.DoesNotContain(
                "ambiguous characters excluded",
                PasswordCharsets.Describe(PasswordCharacters.Alphanumeric, excludeAmbiguous: false),
                StringComparison.Ordinal);
        }

        [Fact]
        public void Entropy_is_the_number_of_choices_times_the_bits_per_choice()
        {
            Assert.Equal(102.3, PasswordStrength.Round(PasswordStrength.EntropyBits(16, 84)));
            Assert.Equal(39.9, PasswordStrength.Round(PasswordStrength.EntropyBits(12, 10)));
        }

        [Theory]
        [InlineData(0, 84)]
        [InlineData(-4, 84)]
        [InlineData(16, 1)]
        [InlineData(16, 0)]
        public void A_choice_that_is_not_a_choice_contributes_no_entropy(int count, int alphabetSize)
        {
            Assert.Equal(0d, PasswordStrength.EntropyBits(count, alphabetSize));
        }

        [Theory]
        [InlineData(0d, "Very weak")]
        [InlineData(27.9d, "Very weak")]
        [InlineData(28d, "Weak")]
        [InlineData(35.9d, "Weak")]
        [InlineData(36d, "Reasonable")]
        [InlineData(59.9d, "Reasonable")]
        [InlineData(60d, "Strong")]
        [InlineData(127.9d, "Strong")]
        [InlineData(128d, "Very strong")]
        [InlineData(256d, "Very strong")]
        public void A_strength_label_follows_the_documented_entropy_thresholds(double entropyBits, string expected)
        {
            Assert.Equal(expected, PasswordStrength.Describe(entropyBits));
        }

        [Fact]
        public void The_word_list_is_free_of_duplicates_and_ordered()
        {
            var words = Wordlist.Words;
            string[] ordered = [.. words.OrderBy(word => word, StringComparer.Ordinal)];

            Assert.Equal(words.Count, words.Distinct(StringComparer.Ordinal).Count());
            Assert.Equal(Wordlist.Count, words.Count);
            Assert.Equal(ordered, words);
        }

        [Fact]
        public void Every_word_is_short_lowercase_and_typable()
        {
            Assert.All(Wordlist.Words, word =>
            {
                Assert.InRange(word.Length, 4, 7);
                Assert.True(word.All(char.IsAsciiLetterLower), $"'{word}' is not plain lowercase ASCII.");
            });
        }

        [Fact]
        public void The_word_list_is_large_enough_for_a_six_word_passphrase_to_be_strong()
        {
            var entropy = PasswordStrength.EntropyBits(6, Wordlist.Count);

            Assert.True(
                Wordlist.Count >= 1024,
                $"The word list has {Wordlist.Count} words, which is fewer than the 1024 assumed by the documentation.");
            Assert.Equal("Strong", PasswordStrength.Describe(entropy));
        }

        [Fact]
        public void A_default_password_spec_is_valid_and_describes_a_strong_password()
        {
            var spec = new PasswordSpec();

            spec.Validate();

            Assert.Equal(16, spec.Length);
            Assert.Equal(PasswordCharacters.All, spec.Characters);
            Assert.Equal(4, spec.SelectedSetCount());
            Assert.True(spec.RequireEachSet);
            Assert.False(spec.ExcludeAmbiguous);
        }

        [Theory]
        [InlineData(3)]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(513)]
        public void A_length_outside_the_documented_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new PasswordSpec { Length = length }.Validate());

            Assert.Contains("between 4 and 512", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_minimum_length_is_always_enough_to_hold_one_character_from_every_set()
        {
            var everySet = new PasswordSpec { Characters = PasswordCharacters.All };

            // This is why requiring every set can never conflict with the length range: the shortest
            // password this API will generate is at least as long as the number of sets. If a set is ever
            // added, this test fails and the minimum length has to be raised with it.
            Assert.True(
                PasswordSpec.MinimumLength >= everySet.SelectedSetCount(),
                "The minimum password length is shorter than the number of character sets, so requiring "
                + "one character from each could not be satisfied at that length.");

            new PasswordSpec
            {
                Length = PasswordSpec.MinimumLength,
                Characters = PasswordCharacters.All,
                RequireEachSet = true
            }.Validate();
        }

        [Fact]
        public void Selecting_no_character_set_is_refused_by_validation()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new PasswordSpec { Characters = PasswordCharacters.None }.Validate());

            Assert.Contains("At least one character set", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(101)]
        public void A_bulk_request_outside_the_documented_range_is_refused(int count)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new BulkPasswordSpec { Count = count }.Validate());

            Assert.Contains("between 1 and 100", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_bulk_request_validates_the_password_options_it_carries()
        {
            Assert.Throws<CryptographicRequestException>(
                () => new BulkPasswordSpec { Password = new PasswordSpec { Length = 2 } }.Validate());
        }

        [Theory]
        [InlineData(2)]
        [InlineData(25)]
        public void A_passphrase_word_count_outside_the_documented_range_is_refused(int words)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new PassphraseSpec { Words = words }.Validate());

            Assert.Contains("between 3 and 24", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(" ")]
        [InlineData("\t")]
        [InlineData("\n")]
        public void A_passphrase_separator_containing_whitespace_is_refused(string separator)
        {
            Assert.Throws<CryptographicRequestException>(
                () => new PassphraseSpec { Separator = separator }.Validate());
        }

        [Fact]
        public void An_over_long_passphrase_separator_is_refused()
        {
            Assert.Throws<CryptographicRequestException>(
                () => new PassphraseSpec { Separator = "-----" }.Validate());
        }

        [Theory]
        [InlineData("")]
        [InlineData("-")]
        [InlineData("_")]
        [InlineData("..")]
        public void A_reasonable_passphrase_separator_is_accepted(string separator)
        {
            new PassphraseSpec { Separator = separator }.Validate();
        }

        [Theory]
        [InlineData(1)]
        [InlineData(13)]
        public void A_pronounceable_syllable_count_outside_the_documented_range_is_refused(int syllables)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new PronounceableSpec { Syllables = syllables }.Validate());

            Assert.Contains("between 2 and 12", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(2)]
        [InlineData(17)]
        public void A_pin_length_outside_the_documented_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new PinSpec { Length = length }.Validate());

            Assert.Contains("between 3 and 16", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(5)]
        public void A_username_word_count_outside_the_documented_range_is_refused(int words)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => new UsernameSpec { Words = words }.Validate());

            Assert.Contains("between 1 and 4", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("!")]
        [InlineData(" ")]
        [InlineData("@@")]
        public void A_username_separator_that_is_not_url_safe_is_refused(string separator)
        {
            Assert.Throws<CryptographicRequestException>(
                () => new UsernameSpec { Separator = separator }.Validate());
        }

        [Fact]
        public void Every_preset_is_uniquely_named_valid_and_listed_in_order()
        {
            var presets = PasswordPresetCatalog.All;
            string[] orderedNames =
            [
                .. presets.Select(preset => preset.Name).OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            ];

            Assert.NotEmpty(presets);
            Assert.Equal(
                presets.Count,
                presets.Select(preset => preset.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());
            Assert.Equal(orderedNames, PasswordPresetCatalog.Names);

            Assert.All(presets, preset =>
            {
                preset.Spec.Validate();
                Assert.False(string.IsNullOrWhiteSpace(preset.Description));
            });
        }

        [Theory]
        [InlineData("password", 16, PasswordCharacters.All)]
        [InlineData("master", 24, PasswordCharacters.All)]
        [InlineData("wifi", 20, PasswordCharacters.Alphanumeric)]
        [InlineData("gaming", 12, PasswordCharacters.Alphanumeric)]
        [InlineData("temporary", 10, PasswordCharacters.Alphanumeric)]
        [InlineData("letters-only", 16, PasswordCharacters.LettersOnly)]
        [InlineData("numbers-only", 12, PasswordCharacters.Digits)]
        [InlineData("32-character", 32, PasswordCharacters.All)]
        public void A_documented_preset_resolves_to_the_documented_options(
            string name,
            int expectedLength,
            PasswordCharacters expectedCharacters)
        {
            var preset = PasswordPresetCatalog.Resolve(name);

            Assert.Equal(name, preset.Name);
            Assert.Equal(expectedLength, preset.Spec.Length);
            Assert.Equal(expectedCharacters, preset.Spec.Characters);
        }

        [Theory]
        [InlineData("WIFI")]
        [InlineData("  wifi  ")]
        [InlineData("WiFi")]
        public void A_preset_resolves_ignoring_case_and_surrounding_whitespace(string name)
        {
            Assert.Equal("wifi", PasswordPresetCatalog.Resolve(name).Name);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void A_missing_preset_asks_for_one_and_lists_what_is_supported(string? name)
        {
            var exception = Assert.Throws<CryptographicRequestException>(() => PasswordPresetCatalog.Resolve(name));

            Assert.Contains("A preset is required", exception.Message, StringComparison.Ordinal);
            Assert.Contains("wifi", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_unknown_preset_is_reported_with_the_supported_presets()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => PasswordPresetCatalog.Resolve("unbreakable"));

            Assert.Contains("Unsupported preset 'unbreakable'", exception.Message, StringComparison.Ordinal);
            Assert.Contains("password", exception.Message, StringComparison.Ordinal);
            Assert.False(PasswordPresetCatalog.TryResolve("unbreakable", out var missing));
            Assert.Null(missing);
        }

        [Fact]
        public void A_preset_that_is_deliberately_weaker_than_the_default_says_so()
        {
            Assert.NotEmpty(PasswordPresetCatalog.Resolve("numbers-only").Warnings);
            Assert.NotEmpty(PasswordPresetCatalog.Resolve("8-character").Warnings);
            Assert.NotEmpty(PasswordPresetCatalog.Resolve("temporary").Warnings);
            Assert.Empty(PasswordPresetCatalog.Resolve("password").Warnings);
        }
    }
}
