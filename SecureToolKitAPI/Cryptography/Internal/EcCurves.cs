using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>Maps requested curve strengths to the NIST named curves supported by this API.</summary>
    internal static class EcCurves
    {
        /// <summary>Returns the named curve matching a requested size in bits.</summary>
        internal static ECCurve FromKeySize(int keySizeBits) => keySizeBits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            521 => ECCurve.NamedCurves.nistP521,
            _ => throw new CryptographicRequestException(
                $"Unsupported elliptic curve size {keySizeBits}. Supported sizes are 256 (P-256), 384 (P-384) and 521 (P-521).")
        };
    }
}
