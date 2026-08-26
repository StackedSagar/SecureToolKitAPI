using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Recovery;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The recovery generator: that backup codes and recovery keys come out at the requested size in the
    /// requested alphabet, that the reported entropy matches what was actually drawn, that the grouping is
    /// presentation only, that every value is independent of every other, and that unusable options are
    /// refused before any randomness is drawn.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything this generator produces is live credential material, so no assertion prints a generated
    /// value. Membership and uniqueness are checked through booleans with a message that describes the
    /// defect instead of showing the value.
    /// </para>
    /// <para>
    /// The expected alphabet is written out here rather than read from the implementation, so a change to
    /// the constant the generator samples from fails these tests instead of travelling through them.
    /// </para>
    /// </remarks>
    public class RecoveryGeneratorTests
    {
        /// <summary>Crockford's Base32 alphabet: the digits and the uppercase letters except I, L, O and U.</summary>
        private const string Crockford32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        /// <summary>The digits, which is all a numeric code may contain.</summary>
        private const string Digits = "0123456789";

        /// <summary>
        /// How many values the uniqueness checks draw. Enough that a generator reusing one would fail
        /// reliably, small enough to keep the suite fast.
        /// </summary>
        private const int Iterations = 50;

        private readonly RecoveryGenerator _generator = new();

        [Fact]
        public void The_default_backup_codes_are_ten_ten_character_codes_in_groups_of_five()
        {
            var result = _generator.GenerateBackupCodes(new BackupCodeSpec());

            Assert.Equal(10, result.Codes.Count);
            Assert.Equal(10, result.Length);

            // Ten characters over 32 symbols is five bits each, so exactly fifty bits.
            Assert.Equal(50d, result.EntropyBitsPerCode);
            Assert.Equal("Reasonable", result.Strength);
            Assert.Equal(
                "10 characters drawn from digits and uppercase letters, excluding I, L, O and U "
                + "(32 character alphabet), written in groups of 5",
                result.Composition);
        }

        [Fact]
        public void A_backup_code_contains_only_the_unambiguous_alphabet_and_the_separators()
        {
            var result = _generator.GenerateBackupCodes(new BackupCodeSpec());

            Assert.All(
                result.Codes,
                code => Assert.True(
                    code.All(character => character == '-' || Crockford32.Contains(character, StringComparison.Ordinal)),
                    "A backup code contained a character outside the alphabet it is supposed to sample from."));
        }

        [Fact]
        public void A_numeric_backup_code_contains_only_digits_and_says_how_much_weaker_it_is()
        {
            var result = _generator.GenerateBackupCodes(
                new BackupCodeSpec { Format = BackupCodeFormat.Numeric });

            Assert.All(
                result.Codes,
                code => Assert.True(
                    code.All(character => character == '-' || Digits.Contains(character, StringComparison.Ordinal)),
                    "A numeric backup code contained something other than a digit."));

            // Ten digits is log2(10) bits each, so a numeric code of the same length is worth far less.
            Assert.Equal(33.2d, result.EntropyBitsPerCode);
            Assert.Equal("Weak", result.Strength);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Digits alone carry about 3.3 bits", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(6, 5, 7)]
        [InlineData(10, 5, 11)]
        [InlineData(12, 4, 14)]
        [InlineData(16, 8, 17)]
        [InlineData(10, 0, 10)]
        [InlineData(10, 10, 10)]
        [InlineData(10, 16, 10)]
        public void Grouping_changes_only_how_a_code_is_written_down(
            int length,
            int groupSize,
            int expectedLength)
        {
            var result = _generator.GenerateBackupCodes(
                new BackupCodeSpec { Count = 3, Length = length, GroupSize = groupSize });

            Assert.All(result.Codes, code => Assert.Equal(expectedLength, code.Length));

            // The separators carry nothing, so the reported figures are about the characters only.
            Assert.Equal(length, result.Length);
            Assert.Equal(length * 5d, result.EntropyBitsPerCode);
        }

        [Fact]
        public void The_codes_in_one_set_are_drawn_independently_of_each_other()
        {
            var result = _generator.GenerateBackupCodes(new BackupCodeSpec { Count = 50, Length = 16 });

            var distinct = new HashSet<string>(result.Codes, StringComparer.Ordinal);

            Assert.Equal(result.Codes.Count, distinct.Count);
        }

        [Fact]
        public void Two_sets_of_backup_codes_never_overlap()
        {
            var first = _generator.GenerateBackupCodes(new BackupCodeSpec { Length = 16 });
            var second = _generator.GenerateBackupCodes(new BackupCodeSpec { Length = 16 });

            Assert.False(
                first.Codes.Intersect(second.Codes, StringComparer.Ordinal).Any(),
                "Two sets of backup codes shared a code, so the randomness is not working.");
        }

        [Fact]
        public void The_backup_code_advisories_cover_single_use_hashing_and_rate_limiting()
        {
            var result = _generator.GenerateBackupCodes(new BackupCodeSpec());

            Assert.Equal(4, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("single use", StringComparison.Ordinal)
                    && warning.Contains("rate-limit", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("hashed with a password-hashing function", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("returned once", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(0, "between 1 and 50")]
        [InlineData(-1, "between 1 and 50")]
        [InlineData(51, "between 1 and 50")]
        public void A_backup_code_count_outside_the_supported_range_is_refused(int count, string expected)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateBackupCodes(new BackupCodeSpec { Count = count }));

            Assert.Contains(expected, exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(5)]
        [InlineData(33)]
        [InlineData(int.MaxValue)]
        public void A_backup_code_length_outside_the_supported_range_is_refused(int length)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateBackupCodes(new BackupCodeSpec { Length = length }));

            Assert.Contains("between 6 and 32 characters", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(17)]
        public void A_group_size_outside_the_supported_range_is_refused(int groupSize)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateBackupCodes(new BackupCodeSpec { GroupSize = groupSize }));

            Assert.Contains("between 0 and 16 characters", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_format_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateBackupCodes(
                    new BackupCodeSpec { Format = (BackupCodeFormat)987 }));

            Assert.Contains("not supported", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_boundaries_of_the_backup_code_ranges_are_accepted()
        {
            var smallest = _generator.GenerateBackupCodes(
                new BackupCodeSpec
                {
                    Count = BackupCodeSpec.MinimumCount,
                    Length = BackupCodeSpec.MinimumLength
                });

            var largest = _generator.GenerateBackupCodes(
                new BackupCodeSpec
                {
                    Count = BackupCodeSpec.MaximumCount,
                    Length = BackupCodeSpec.MaximumLength
                });

            Assert.Single(smallest.Codes);
            Assert.Equal(BackupCodeSpec.MinimumLength, smallest.Length);
            Assert.Equal(BackupCodeSpec.MaximumCount, largest.Codes.Count);
            Assert.Equal(BackupCodeSpec.MaximumLength, largest.Length);
        }

        [Fact]
        public void The_default_recovery_key_is_five_groups_of_five_worth_a_hundred_and_twenty_five_bits()
        {
            var result = _generator.GenerateRecoveryKey(new RecoveryKeySpec());

            Assert.Equal(25, result.Characters);
            Assert.Equal(5, result.Groups);

            // Twenty-five characters over 32 symbols, five bits each.
            Assert.Equal(125d, result.EntropyBits);
            Assert.Equal("Strong", result.Strength);

            // Twenty-five characters and the four separators between five groups.
            Assert.Equal(29, result.Value.Length);
            Assert.Equal(5, result.Value.Split('-').Length);
        }

        [Fact]
        public void A_recovery_key_contains_only_the_unambiguous_alphabet_and_the_separators()
        {
            var result = _generator.GenerateRecoveryKey(new RecoveryKeySpec());

            Assert.True(
                result.Value.All(character =>
                    character == '-' || Crockford32.Contains(character, StringComparison.Ordinal)),
                "The recovery key contained a character outside the alphabet it is supposed to sample from.");
        }

        [Theory]
        [InlineData(2, 4, 8, 9)]
        [InlineData(4, 5, 20, 23)]
        [InlineData(8, 8, 64, 71)]
        [InlineData(16, 4, 64, 79)]
        public void A_recovery_key_has_the_size_its_groups_imply(
            int groups,
            int groupSize,
            int expectedCharacters,
            int expectedLength)
        {
            var result = _generator.GenerateRecoveryKey(
                new RecoveryKeySpec { Groups = groups, GroupSize = groupSize });

            Assert.Equal(expectedCharacters, result.Characters);
            Assert.Equal(groups, result.Groups);
            Assert.Equal(expectedLength, result.Value.Length);
            Assert.Equal(expectedCharacters * 5d, result.EntropyBits);
        }

        [Fact]
        public void A_recovery_key_that_would_be_attacked_offline_is_told_when_it_is_too_short()
        {
            var weak = _generator.GenerateRecoveryKey(new RecoveryKeySpec { Groups = 2, GroupSize = 4 });
            var strong = _generator.GenerateRecoveryKey(new RecoveryKeySpec());

            Assert.Contains(
                weak.Warnings,
                warning => warning.Contains("below the 100 bits", StringComparison.Ordinal));
            Assert.DoesNotContain(
                strong.Warnings,
                warning => warning.Contains("below the 100 bits", StringComparison.Ordinal));
        }

        [Fact]
        public void The_recovery_key_advisories_say_how_to_store_it_and_how_to_verify_it()
        {
            var result = _generator.GenerateRecoveryKey(new RecoveryKeySpec());

            Assert.Equal(3, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("never in the same place as the password", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("Ignore the separators when verifying", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("returned once", StringComparison.Ordinal));
        }

        [Fact]
        public void Every_recovery_key_is_drawn_independently()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);

            for (var iteration = 0; iteration < Iterations; iteration++)
            {
                seen.Add(_generator.GenerateRecoveryKey(new RecoveryKeySpec()).Value);
            }

            Assert.Equal(Iterations, seen.Count);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(0)]
        [InlineData(17)]
        public void A_recovery_key_group_count_outside_the_supported_range_is_refused(int groups)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateRecoveryKey(new RecoveryKeySpec { Groups = groups }));

            Assert.Contains("between 2 and 16", exception.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(3)]
        [InlineData(0)]
        [InlineData(9)]
        public void A_recovery_key_group_size_outside_the_supported_range_is_refused(int groupSize)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateRecoveryKey(new RecoveryKeySpec { GroupSize = groupSize }));

            Assert.Contains("between 4 and 8 characters", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Generating_without_options_is_rejected_rather_than_silently_defaulted()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateBackupCodes(null!));
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateRecoveryKey(null!));
        }
    }
}
