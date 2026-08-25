namespace SecureToolKitAPI.Tests.TestSupport
{
    /// <summary>Message samples used to exercise the round trip of every encryption method.</summary>
    public static class TestMessages
    {
        /// <summary>An ordinary short message.</summary>
        public const string Normal = "Hello World";

        /// <summary>An empty message, which every method must accept.</summary>
        public const string Empty = "";

        /// <summary>Multi-byte characters, including characters outside the basic multilingual plane.</summary>
        public const string Unicode = "Καλημέρα κόσμε — こんにちは世界 — मंगलमय प्रभात — 🔐🧩";

        /// <summary>Punctuation and characters that are significant in JSON, XML and shells.</summary>
        public const string SpecialCharacters = "\"quoted\" & <tagged> \\slash\\ 'single' {json:1} $var `cmd` \r\n\ttabbed; 100%";

        /// <summary>Whitespace only, which must survive the round trip unchanged.</summary>
        public const string WhitespaceOnly = "   \t  \r\n ";

        /// <summary>A message that comfortably exceeds a single AES block and a typical buffer size.</summary>
        public static string Long { get; } = string.Concat(Enumerable.Repeat("The quick brown fox jumps over the lazy dog. ", 2_000));

        /// <summary>
        /// A message sized to just fit RSA-OAEP with SHA-256 under a 2048-bit key (190 bytes).
        /// </summary>
        public static string RsaMaximumFor2048 { get; } = new string('x', 190);

        /// <summary>
        /// A message one byte larger than a 2048-bit RSA-OAEP key can carry.
        /// </summary>
        public static string RsaOversizedFor2048 { get; } = new string('x', 191);

        /// <summary>
        /// Messages every method must round trip, sized so that RSA's key-bound limit is respected.
        /// </summary>
        public static IEnumerable<string> UniversallySupported()
        {
            yield return Normal;
            yield return Empty;
            yield return Unicode;
            yield return SpecialCharacters;
            yield return WhitespaceOnly;
        }
    }
}
