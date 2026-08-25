using SecureToolKitAPI.Application;
using SecureToolKitAPI.Cryptography.Abstractions;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// How a caller-supplied method identifier is turned into an implementation, and how wiring
    /// mistakes are surfaced.
    /// </summary>
    public class CryptographicMethodRegistryTests
    {
        [Theory]
        [InlineData("first")]
        [InlineData("FIRST")]
        [InlineData("First")]
        [InlineData("  first  ")]
        [InlineData("uno")]
        [InlineData("UNO")]
        public void An_identifier_resolves_by_name_or_alias_ignoring_case_and_whitespace(string identifier)
        {
            var registry = Registry();

            Assert.Equal("first", registry.Resolve(identifier).Name);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void A_missing_identifier_asks_for_one_and_lists_what_is_supported(string? identifier)
        {
            var registry = Registry();

            var exception = Assert.Throws<CryptographicRequestException>(() => registry.Resolve(identifier));

            Assert.Contains("A method is required", exception.Message, StringComparison.Ordinal);
            Assert.Contains("first, second", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_unknown_identifier_is_reported_with_the_supported_methods()
        {
            var registry = Registry();

            var exception = Assert.Throws<CryptographicRequestException>(() => registry.Resolve("third"));

            Assert.Contains("Unsupported method 'third'", exception.Message, StringComparison.Ordinal);
            Assert.Contains("first, second", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void TryResolve_reports_success_without_throwing()
        {
            var registry = Registry();

            Assert.True(registry.TryResolve("dos", out var resolved));
            Assert.Equal("second", resolved!.Name);

            Assert.False(registry.TryResolve("third", out var missing));
            Assert.Null(missing);

            Assert.False(registry.TryResolve(null, out _));
        }

        [Fact]
        public void Methods_are_listed_in_a_stable_alphabetical_order()
        {
            var registry = new CryptographicMethodRegistry<ICryptographicMethod>(
                new ICryptographicMethod[]
                {
                    new FakeMethod("second", new[] { "dos" }),
                    new FakeMethod("first", new[] { "uno" })
                });

            Assert.Equal(new[] { "first", "second" }, registry.SupportedNames);
            Assert.Equal(new[] { "first", "second" }, registry.Methods.Select(method => method.Name));
        }

        [Fact]
        public void Two_methods_claiming_the_same_name_fail_at_construction()
        {
            var exception = Assert.Throws<InvalidOperationException>(
                () => new CryptographicMethodRegistry<ICryptographicMethod>(
                    new ICryptographicMethod[]
                    {
                        new FakeMethod("first", Array.Empty<string>()),
                        new FakeMethod("first", Array.Empty<string>())
                    }));

            Assert.Contains("more than one", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void An_alias_that_collides_with_another_method_fails_at_construction()
        {
            Assert.Throws<InvalidOperationException>(
                () => new CryptographicMethodRegistry<ICryptographicMethod>(
                    new ICryptographicMethod[]
                    {
                        new FakeMethod("first", new[] { "shared" }),
                        new FakeMethod("second", new[] { "SHARED" })
                    }));
        }

        [Fact]
        public void A_blank_identifier_fails_at_construction()
        {
            var exception = Assert.Throws<InvalidOperationException>(
                () => new CryptographicMethodRegistry<ICryptographicMethod>(
                    new ICryptographicMethod[] { new FakeMethod("first", new[] { "  " }) }));

            Assert.Contains("blank identifier", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_missing_method_collection_is_rejected()
        {
            Assert.Throws<ArgumentNullException>(
                () => new CryptographicMethodRegistry<ICryptographicMethod>(null!));
        }

        private static CryptographicMethodRegistry<ICryptographicMethod> Registry() =>
            new(new ICryptographicMethod[]
            {
                new FakeMethod("first", new[] { "uno" }),
                new FakeMethod("second", new[] { "dos" })
            });

        /// <summary>A stand-in method used to test resolution without depending on a real algorithm.</summary>
        private sealed record FakeMethod(string Name, IReadOnlyCollection<string> Aliases) : ICryptographicMethod
        {
            public string Description => "Test double.";
        }
    }
}
