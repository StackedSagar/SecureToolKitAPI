using System.Security.Cryptography;
using System.Text;
using SecureToolKitAPI.Cryptography.Abstractions;
using SecureToolKitAPI.Cryptography.Network;
using Xunit;

namespace SecureToolKitAPI.Tests.Unit
{
    /// <summary>
    /// The SSH key generator: that the public key is the encoding OpenSSH actually reads, that the private key
    /// really is the other half of it, that the fingerprint is the fingerprint of that key, and that options
    /// which would produce an unusable or unsafe key are refused before anything is generated.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The public key blob is parsed here rather than compared against a stored string, and it is parsed by
    /// this file's own reader rather than by the writer that produced it. That is the point of the exercise: a
    /// test that called <c>SshWireFormat</c> to check <c>SshWireFormat</c> would agree with any mistake it
    /// made. The field layout the reader expects comes from RFC 4253 and RFC 5656 and was checked against
    /// <c>ssh-keygen</c> output while this was written.
    /// </para>
    /// <para>
    /// The private key is secret material and is never printed. It is read for exactly one purpose — to
    /// re-import it and confirm its public half matches the public key that was published — and every
    /// assertion touching it is a boolean with a message that names the defect instead of showing the key.
    /// The public key and the fingerprint are not secret and may appear in failure output.
    /// </para>
    /// </remarks>
    public class NetworkKeyGeneratorTests
    {
        /// <summary>The PEM label of an unencrypted PKCS#8 private key.</summary>
        private const string PemHeader = "-----BEGIN PRIVATE KEY-----";

        /// <summary>The closing PEM label of an unencrypted PKCS#8 private key.</summary>
        private const string PemFooter = "-----END PRIVATE KEY-----";

        /// <summary>
        /// How many keys the uniqueness check draws. Small, because each one is a real key generation, and
        /// ECDSA is used so that it stays fast.
        /// </summary>
        private const int Iterations = 5;

        /// <summary>
        /// Length of each substring the leak check looks for. Long enough that a match cannot be a chance
        /// collision of Base64 characters, short enough that several fit in the half of the key body being
        /// searched.
        /// </summary>
        private const int ChunkLength = 24;

        /// <summary>How many chunks the leak check samples from the private key body.</summary>
        private const int ChunkCount = 4;

        private readonly NetworkKeyGenerator _generator = new();

        [Fact]
        public void The_default_key_is_rsa_at_three_thousand_and_seventy_two_bits()
        {
            var result = _generator.GenerateSshKey(new SshKeySpec());

            Assert.Equal("rsa", result.Algorithm);
            Assert.Equal("ssh-rsa", result.KeyType);
            Assert.Equal(3072, result.Bits);

            // 3072 bits is the size NIST puts at the 128-bit level, which is the number worth comparing
            // against a symmetric key rather than the 3072.
            Assert.Equal(128, result.SecurityStrengthBits);
            Assert.Equal(
                "RSA 3072-bit key pair, comparable to a 128-bit symmetric key",
                result.Composition);
            Assert.Equal("Unencrypted PKCS#8 private key in PEM.", result.PrivateKeyFormat);
            Assert.Null(result.Comment);
        }

        [Fact]
        public void The_public_key_is_one_line_shaped_the_way_an_authorized_keys_entry_is()
        {
            var result = _generator.GenerateSshKey(new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa });

            // A newline here would end the authorized_keys entry early and let the rest be read as a second
            // authorized key, so the absence of one is the assertion that matters most on this line.
            Assert.False(
                result.PublicKey.Contains('\n', StringComparison.Ordinal)
                || result.PublicKey.Contains('\r', StringComparison.Ordinal),
                "The public key contained a line break, so it would not be one authorized_keys entry.");

            var parts = result.PublicKey.Split(' ');

            Assert.Equal(2, parts.Length);
            Assert.Equal(result.KeyType, parts[0]);
            Assert.False(string.IsNullOrEmpty(parts[1]), "The public key line carried no key data.");
        }

        [Theory]
        [InlineData(2048, 112)]
        [InlineData(3072, 128)]
        [InlineData(4096, 128)]
        public void An_rsa_public_key_carries_the_modulus_and_exponent_of_the_key_that_was_generated(
            int bits,
            int expectedStrength)
        {
            var result = _generator.GenerateSshKey(new SshKeySpec { Bits = bits });

            Assert.Equal(bits, result.Bits);
            Assert.Equal(expectedStrength, result.SecurityStrengthBits);
            Assert.Equal("ssh-rsa", result.KeyType);

            var fields = Fields(result.PublicKey);

            // ssh-rsa is three fields: the key type, then the exponent and the modulus as signed integers.
            Assert.Equal(3, fields.Length);
            Assert.Equal("ssh-rsa", Ascii(fields[0]));

            var exponent = Trim(fields[1]);
            var modulus = Trim(fields[2]);

            // 65537 is .NET's default public exponent. It is pinned because a different one would change what
            // every server sees, so a change here is worth failing over rather than passing quietly.
            Assert.Equal(new byte[] { 0x01, 0x00, 0x01 }, exponent);

            // An RSA modulus of n bits always has its top bit set, so exactly n/8 bytes after trimming means
            // exactly n bits — and it is why the encoded field is one byte longer, to keep it positive.
            Assert.Equal(bits / 8, modulus.Length);
            Assert.True(
                (modulus[0] & 0x80) != 0,
                "The modulus was shorter than the requested key size.");
            Assert.Equal(bits / 8 + 1, fields[2].Length);
        }

        [Theory]
        [InlineData(256, 32, 128)]
        [InlineData(384, 48, 192)]
        [InlineData(521, 66, 256)]
        public void An_ecdsa_public_key_carries_the_curve_name_and_the_uncompressed_point(
            int bits,
            int coordinateBytes,
            int expectedStrength)
        {
            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Bits = bits });

            var curve = $"nistp{bits}";

            Assert.Equal("ecdsa", result.Algorithm);
            Assert.Equal($"ecdsa-sha2-{curve}", result.KeyType);
            Assert.Equal(bits, result.Bits);
            Assert.Equal(expectedStrength, result.SecurityStrengthBits);
            Assert.Equal(
                $"ECDSA key pair on {curve} (NIST P-{bits}), comparable to a {expectedStrength}-bit "
                + "symmetric key",
                result.Composition);

            var fields = Fields(result.PublicKey);

            // RFC 5656 names the curve twice: once inside the key type and once on its own.
            Assert.Equal(3, fields.Length);
            Assert.Equal($"ecdsa-sha2-{curve}", Ascii(fields[0]));
            Assert.Equal(curve, Ascii(fields[1]));

            // The point is SEC 1 uncompressed: a 0x04 marker and the two coordinates, each padded to the
            // field size. 521 bits needs 66 bytes, not 65, because the field is not a whole number of bytes.
            Assert.Equal(1 + (coordinateBytes * 2), fields[2].Length);
            Assert.Equal(0x04, fields[2][0]);
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        public void An_rsa_private_key_is_the_other_half_of_the_public_key_that_was_published(int bits)
        {
            var result = _generator.GenerateSshKey(new SshKeySpec { Bits = bits });

            using var rsa = RSA.Create();
            rsa.ImportFromPem(result.PrivateKey);

            var reimported = rsa.ExportParameters(includePrivateParameters: false);
            var fields = Fields(result.PublicKey);

            // If these disagree, the response handed out a public key for one key and the private half of
            // another, which no amount of correct formatting would rescue.
            Assert.True(
                Trim(reimported.Modulus ?? []).SequenceEqual(Trim(fields[2])),
                "The private key's modulus did not match the published public key.");
            Assert.True(
                Trim(reimported.Exponent ?? []).SequenceEqual(Trim(fields[1])),
                "The private key's exponent did not match the published public key.");
            Assert.Equal(bits, rsa.KeySize);
        }

        [Theory]
        [InlineData(256, 32)]
        [InlineData(384, 48)]
        [InlineData(521, 66)]
        public void An_ecdsa_private_key_is_the_other_half_of_the_public_key_that_was_published(
            int bits,
            int coordinateBytes)
        {
            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Bits = bits });

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(result.PrivateKey);

            var point = ecdsa.ExportParameters(includePrivateParameters: false).Q;
            var published = Fields(result.PublicKey)[2];

            Assert.True(
                (point.X ?? []).SequenceEqual(published[1..(1 + coordinateBytes)]),
                "The private key's public point X did not match the published public key.");
            Assert.True(
                (point.Y ?? []).SequenceEqual(published[(1 + coordinateBytes)..]),
                "The private key's public point Y did not match the published public key.");
            Assert.Equal(bits, ecdsa.KeySize);
        }

        [Theory]
        [InlineData(SshKeyAlgorithm.Rsa, 2048)]
        [InlineData(SshKeyAlgorithm.Ecdsa, 256)]
        public void The_private_key_is_an_unencrypted_pkcs8_pem(SshKeyAlgorithm algorithm, int bits)
        {
            var result = _generator.GenerateSshKey(new SshKeySpec { Algorithm = algorithm, Bits = bits });
            var pem = result.PrivateKey.Trim();

            Assert.True(
                pem.StartsWith(PemHeader, StringComparison.Ordinal),
                "The private key did not open with the PKCS#8 PEM label.");
            Assert.True(
                pem.EndsWith(PemFooter, StringComparison.Ordinal),
                "The private key did not close with the PKCS#8 PEM label.");

            // The response says the key is unencrypted, so it must not be an encrypted container: an
            // "ENCRYPTED PRIVATE KEY" label here would make the advisory a lie in the safe direction, and the
            // OpenSSH label would make the format field wrong.
            Assert.False(
                pem.Contains("ENCRYPTED", StringComparison.Ordinal),
                "The private key label disagreed with the format the response reported.");
            Assert.False(
                pem.Contains("OPENSSH", StringComparison.Ordinal),
                "The private key label disagreed with the format the response reported.");
        }

        [Theory]
        [InlineData(SshKeyAlgorithm.Rsa, 2048)]
        [InlineData(SshKeyAlgorithm.Ecdsa, 256)]
        [InlineData(SshKeyAlgorithm.Ecdsa, 521)]
        public void The_fingerprint_is_the_sha256_of_the_public_key_that_was_published(
            SshKeyAlgorithm algorithm,
            int bits)
        {
            var result = _generator.GenerateSshKey(new SshKeySpec { Algorithm = algorithm, Bits = bits });

            // Recomputed here from the published key rather than trusted, which is the same calculation
            // ssh-keygen -lf performs.
            var expected = "SHA256:"
                + Convert.ToBase64String(SHA256.HashData(Blob(result.PublicKey))).TrimEnd('=');

            Assert.Equal(expected, result.Fingerprint);

            // A fingerprint is a hash of a public value, so it is safe to show: 7 characters of prefix and 43
            // of unpadded Base64 over a 32-byte digest.
            Assert.Equal(50, result.Fingerprint.Length);
            Assert.False(
                result.Fingerprint.Contains('=', StringComparison.Ordinal),
                "The fingerprint carried Base64 padding, which ssh-keygen does not print.");
        }

        [Fact]
        public void A_comment_is_appended_to_the_public_key_line_and_reported_back()
        {
            const string comment = "deploy@build-agent";

            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Comment = comment });

            var parts = result.PublicKey.Split(' ');

            Assert.Equal(3, parts.Length);
            Assert.Equal(comment, parts[2]);
            Assert.Equal(comment, result.Comment);
        }

        [Fact]
        public void A_comment_keeps_its_internal_spaces_and_loses_its_surrounding_ones()
        {
            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Comment = "  deploy key 2026  " });

            Assert.Equal("deploy key 2026", result.Comment);
            Assert.True(
                result.PublicKey.EndsWith(" deploy key 2026", StringComparison.Ordinal),
                "The comment did not end the public key line as it was given.");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void A_missing_or_blank_comment_leaves_the_public_key_line_without_one(string? comment)
        {
            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Comment = comment });

            Assert.Null(result.Comment);
            Assert.Equal(2, result.PublicKey.Split(' ').Length);
            Assert.False(
                result.PublicKey.EndsWith(' '),
                "The public key line ended with a trailing space where a comment would have been.");
        }

        [Theory]
        [InlineData("deploy\nssh-rsa AAAA")]
        [InlineData("deploy\r\nroot@elsewhere")]
        [InlineData("deploy\tagent")]
        [InlineData("deployé")]
        public void A_comment_that_could_not_sit_on_one_line_is_refused(string comment)
        {
            // The first two cases are the ones that matter: a newline in the comment would close the
            // authorized_keys entry and let whatever followed be read as a second authorized key.
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateSshKey(new SshKeySpec { Comment = comment }));

            Assert.Contains("printable ASCII", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void The_accepted_comment_characters_are_exactly_printable_ascii()
        {
            // Checked over the whole range rather than with a handful of examples, and against the spec rather
            // than through a generated key, so the boundary is pinned exactly and nothing is generated: space
            // (32) and tilde (126) are in, and the control character below one and the delete above the other
            // are out.
            for (var code = 0; code <= 0x2FFF; code++)
            {
                var character = (char)code;

                // Padded on both sides so that a whitespace character is not simply trimmed away, which would
                // make it a blank comment rather than an invalid one.
                var spec = new SshKeySpec { Comment = "a" + character + "b" };
                var printable = code is >= ' ' and <= '~';

                if (printable)
                {
                    spec.Validate();
                    continue;
                }

                var exception = Record.Exception(spec.Validate);

                Assert.True(
                    exception is CryptographicRequestException,
                    $"A comment containing character {code} was not refused as unprintable.");
            }
        }

        [Fact]
        public void A_comment_longer_than_the_maximum_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateSshKey(
                    new SshKeySpec { Comment = new string('c', SshKeySpec.MaximumCommentLength + 1) }));

            Assert.Contains("128 characters or fewer", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_comment_at_exactly_the_maximum_length_is_accepted()
        {
            var comment = new string('c', SshKeySpec.MaximumCommentLength);

            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Comment = comment });

            Assert.Equal(comment, result.Comment);
        }

        [Theory]
        [InlineData(SshKeyAlgorithm.Rsa, 1024)]
        [InlineData(SshKeyAlgorithm.Rsa, 2047)]
        [InlineData(SshKeyAlgorithm.Rsa, 8192)]
        [InlineData(SshKeyAlgorithm.Rsa, 256)]
        [InlineData(SshKeyAlgorithm.Rsa, 0)]
        [InlineData(SshKeyAlgorithm.Rsa, -1)]
        [InlineData(SshKeyAlgorithm.Ecdsa, 512)]
        [InlineData(SshKeyAlgorithm.Ecdsa, 255)]
        [InlineData(SshKeyAlgorithm.Ecdsa, 2048)]
        [InlineData(SshKeyAlgorithm.Ecdsa, int.MaxValue)]
        public void A_key_size_the_api_does_not_support_is_refused_before_anything_is_generated(
            SshKeyAlgorithm algorithm,
            int bits)
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateSshKey(new SshKeySpec { Algorithm = algorithm, Bits = bits }));

            Assert.Contains("Supported sizes are:", exception.Message, StringComparison.Ordinal);

            // The sizes each algorithm accepts are different, so the message has to name the right set — 1024
            // is not merely unsupported, it is unsupported for RSA specifically.
            Assert.Contains(
                algorithm is SshKeyAlgorithm.Ecdsa ? "ecdsa" : "rsa",
                exception.Message,
                StringComparison.Ordinal);
        }

        [Fact]
        public void An_algorithm_outside_the_enumeration_is_refused()
        {
            var exception = Assert.Throws<CryptographicRequestException>(
                () => _generator.GenerateSshKey(new SshKeySpec { Algorithm = (SshKeyAlgorithm)77 }));

            Assert.Contains("not supported", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Generating_without_options_is_rejected_rather_than_silently_defaulted()
        {
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateSshKey(null!));
        }

        [Fact]
        public void Two_key_pairs_are_never_the_same()
        {
            var fingerprints = new HashSet<string>(StringComparer.Ordinal);

            for (var iteration = 0; iteration < Iterations; iteration++)
            {
                fingerprints.Add(
                    _generator.GenerateSshKey(
                        new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa }).Fingerprint);
            }

            // Fingerprints stand in for the keys here: they identify a key uniquely and are public, so a
            // failure prints nothing secret.
            Assert.Equal(Iterations, fingerprints.Count);
        }

        [Fact]
        public void The_catalogue_lists_every_supported_combination_with_one_default()
        {
            var catalogue = _generator.SshKeyTypes();

            Assert.Equal(
                new[] { "rsa", "rsa", "rsa", "ecdsa", "ecdsa", "ecdsa" },
                catalogue.Select(entry => entry.Algorithm).ToArray());
            Assert.Equal(
                new[] { 2048, 3072, 4096, 256, 384, 521 },
                catalogue.Select(entry => entry.Bits).ToArray());
            Assert.Equal(
                new[]
                {
                    "ssh-rsa",
                    "ssh-rsa",
                    "ssh-rsa",
                    "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384",
                    "ecdsa-sha2-nistp521"
                },
                catalogue.Select(entry => entry.KeyType).ToArray());

            var defaults = catalogue.Where(entry => entry.IsDefault).ToArray();

            Assert.Single(defaults);
            Assert.Equal("rsa", defaults[0].Algorithm);
            Assert.Equal(3072, defaults[0].Bits);
            Assert.All(catalogue, entry => Assert.False(
                string.IsNullOrWhiteSpace(entry.Notes),
                "A catalogue entry had no notes."));
        }

        [Fact]
        public void The_catalogue_agrees_with_what_the_generator_would_actually_produce()
        {
            // Advertising a combination this API would then reject, or reporting a strength that a generated
            // key does not have, would send a caller down a path that fails later.
            foreach (var entry in _generator.SshKeyTypes())
            {
                var spec = new SshKeySpec
                {
                    Algorithm = NetworkOptions.ParseSshAlgorithm(entry.Algorithm),
                    Bits = entry.Bits
                };

                spec.Validate();

                Assert.Equal(entry.KeyType, spec.KeyTypeName);
                Assert.Equal(entry.SecurityStrengthBits, spec.SecurityStrengthBits);
                Assert.Equal(entry.Algorithm, spec.AlgorithmName);
            }
        }

        [Fact]
        public void The_catalogue_is_the_same_list_every_time_it_is_asked_for()
        {
            // It is built once and shared, which is only safe because nothing in it varies per caller.
            Assert.Same(_generator.SshKeyTypes(), _generator.SshKeyTypes());
            Assert.Same(_generator.SshKeyTypes(), new NetworkKeyGenerator().SshKeyTypes());
        }

        [Fact]
        public void The_advisories_say_the_key_crossed_a_network_and_came_back_unencrypted()
        {
            var result = _generator.GenerateSshKey(new SshKeySpec { Bits = 2048 });

            Assert.Equal(7, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("over the network", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("not encrypted", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("authorized_keys", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("ssh-keygen -lf", StringComparison.Ordinal));

            // The absence of ed25519 is a deliberate limitation, so it is stated rather than left to be
            // discovered.
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("ed25519", StringComparison.Ordinal));

            // 2048 is the one supported size below the 128-bit level, and the response says so.
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("112-bit security level", StringComparison.Ordinal));
        }

        [Fact]
        public void The_ecdsa_advisories_warn_that_a_host_may_refuse_the_key_type()
        {
            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Ecdsa, Bits = 521 });

            Assert.Equal(7, result.Warnings.Count);
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("nistp521", StringComparison.Ordinal));
            Assert.Contains(
                result.Warnings,
                warning => warning.Contains("least widely deployed", StringComparison.Ordinal));
        }

        [Fact]
        public void No_field_that_is_meant_to_be_publishable_contains_the_private_key()
        {
            var result = _generator.GenerateSshKey(
                new SshKeySpec { Algorithm = SshKeyAlgorithm.Rsa, Comment = "deploy@build-agent" });

            // The public key, the fingerprint and the descriptive text are all meant to be copied around
            // freely, so none of them may carry any part of the private key's Base64 body.
            var body = string.Concat(
                result.PrivateKey
                    .Split('\n')
                    .Select(line => line.Trim())
                    .Where(line => line.Length > 0 && !line.StartsWith("-----", StringComparison.Ordinal)));

            // The sampling below reads from the midpoint onwards, so the body has to be at least twice the
            // span being sampled for the last chunk to stay inside it.
            Assert.True(
                body.Length >= ChunkCount * ChunkLength * 2,
                "The private key body was too short to check for a partial leak.");

            // Chunks are taken from the second half of the body rather than the whole of it. Looking for the
            // entire body would only catch a wholesale copy, and a leak of part of a private key is just as
            // serious; the second half is where an RSA PKCS#8 key keeps the private exponent and the primes,
            // so a match there cannot be explained away as the modulus that legitimately appears in both
            // halves of the pair.
            var chunks = Enumerable
                .Range(0, ChunkCount)
                .Select(index => body.Substring(
                    (body.Length / 2) + (index * ChunkLength),
                    ChunkLength))
                .ToArray();

            var publishable = new (string Field, string Value)[]
            {
                ("public key", result.PublicKey),
                ("fingerprint", result.Fingerprint),
                ("composition", result.Composition),
                ("key type", result.KeyType),
                ("private key format", result.PrivateKeyFormat),
                ("comment", result.Comment ?? string.Empty)
            };

            foreach (var (field, value) in publishable)
            {
                foreach (var chunk in chunks)
                {
                    // The message names the field and never shows the chunk, so a failure reports the leak
                    // without printing the key material that leaked.
                    Assert.False(
                        value.Contains(chunk, StringComparison.Ordinal),
                        $"The {field}, which is meant to be publishable, contained part of the private key.");
                }
            }

            foreach (var warning in result.Warnings)
            {
                foreach (var chunk in chunks)
                {
                    Assert.False(
                        warning.Contains(chunk, StringComparison.Ordinal),
                        "An advisory contained part of the private key.");
                }
            }
        }

        /// <summary>
        /// The raw public key blob from an <c>authorized_keys</c> line: the Base64 in the second field,
        /// decoded.
        /// </summary>
        /// <param name="publicKeyLine">The public key as returned.</param>
        private static byte[] Blob(string publicKeyLine) =>
            Convert.FromBase64String(publicKeyLine.Split(' ')[1]);

        /// <summary>
        /// Splits a public key blob into its length-prefixed fields, checking as it goes that no length
        /// prefix points past the end.
        /// </summary>
        /// <param name="publicKeyLine">The public key as returned.</param>
        /// <returns>The fields, in order.</returns>
        /// <remarks>
        /// This reader is deliberately independent of the writer under test. A four-byte big-endian length
        /// followed by that many bytes is the whole of the framing in RFC 4253, so there is not much to get
        /// wrong on this side.
        /// </remarks>
        private static byte[][] Fields(string publicKeyLine)
        {
            var blob = Blob(publicKeyLine);
            var fields = new List<byte[]>();
            var offset = 0;

            while (offset < blob.Length)
            {
                Assert.True(
                    offset + 4 <= blob.Length,
                    "The public key blob ended in the middle of a length prefix.");

                var length = (blob[offset] << 24)
                    | (blob[offset + 1] << 16)
                    | (blob[offset + 2] << 8)
                    | blob[offset + 3];

                offset += 4;

                Assert.True(
                    length >= 0 && offset + length <= blob.Length,
                    "A length prefix in the public key blob ran past the end of the blob.");

                fields.Add(blob[offset..(offset + length)]);
                offset += length;
            }

            return [.. fields];
        }

        /// <summary>Reads a blob field as the ASCII name it is meant to be.</summary>
        /// <param name="field">The field bytes.</param>
        private static string Ascii(byte[] field) => Encoding.ASCII.GetString(field);

        /// <summary>Strips the leading zero bytes an <c>mpint</c> may carry to stay positive.</summary>
        /// <param name="value">The field bytes.</param>
        private static byte[] Trim(byte[] value)
        {
            var start = 0;

            while (start < value.Length && value[start] == 0)
            {
                start++;
            }

            return value[start..];
        }
    }
}
