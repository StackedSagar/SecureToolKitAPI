using System.Security.Cryptography;
using SecureToolKitAPI.Cryptography.Abstractions;

namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// Imports caller-supplied key material using the built-in .NET importers, accepting the formats
    /// this API's key-generation endpoints emit and translating import failures into safe errors.
    /// </summary>
    internal static class KeyImport
    {
        /// <summary>Smallest RSA modulus accepted for encryption.</summary>
        internal const int MinimumRsaKeySizeBits = 2048;

        /// <summary>Imports an RSA public key in PKCS#1 <c>RSAPublicKey</c> or X.509 SubjectPublicKeyInfo form.</summary>
        internal static RSA ImportRsaPublicKey(byte[] keyBytes)
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportRSAPublicKey(keyBytes, out _);
                return rsa;
            }
            catch (CryptographicException)
            {
                rsa.Dispose();
            }

            rsa = RSA.Create();
            try
            {
                rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                return rsa;
            }
            catch (CryptographicException)
            {
                rsa.Dispose();
                throw new CryptographicRequestException(
                    "The supplied key is not a valid RSA public key. Expected PKCS#1 RSAPublicKey or SubjectPublicKeyInfo, Base64 encoded.");
            }
        }

        /// <summary>Imports an RSA private key in PKCS#1 <c>RSAPrivateKey</c> or PKCS#8 form.</summary>
        internal static RSA ImportRsaPrivateKey(byte[] keyBytes)
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportRSAPrivateKey(keyBytes, out _);
                return rsa;
            }
            catch (CryptographicException)
            {
                rsa.Dispose();
            }

            rsa = RSA.Create();
            try
            {
                rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                return rsa;
            }
            catch (CryptographicException)
            {
                rsa.Dispose();
                throw new CryptographicRequestException(
                    "The supplied key is not a valid RSA private key. Expected PKCS#1 RSAPrivateKey or PKCS#8, Base64 encoded.");
            }
        }

        /// <summary>Rejects RSA keys that are too small to be used safely.</summary>
        internal static void EnsureRsaKeySizeAllowed(RSA rsa)
        {
            if (rsa.KeySize < MinimumRsaKeySizeBits)
            {
                throw new CryptographicRequestException(
                    $"RSA keys smaller than {MinimumRsaKeySizeBits} bits are not accepted for encryption.");
            }
        }

        /// <summary>Imports an ECDH public key in X.509 SubjectPublicKeyInfo form.</summary>
        internal static ECDiffieHellman ImportEcdhPublicKey(byte[] keyBytes)
        {
            var ecdh = ECDiffieHellman.Create();
            try
            {
                ecdh.ImportSubjectPublicKeyInfo(keyBytes, out _);
                return ecdh;
            }
            catch (CryptographicException)
            {
                ecdh.Dispose();
                throw new CryptographicRequestException(
                    "The supplied key is not a valid elliptic-curve public key. Expected SubjectPublicKeyInfo, Base64 encoded.");
            }
        }

        /// <summary>Imports an ECDH private key in PKCS#8 form.</summary>
        internal static ECDiffieHellman ImportEcdhPrivateKey(byte[] keyBytes)
        {
            var ecdh = ECDiffieHellman.Create();
            try
            {
                ecdh.ImportPkcs8PrivateKey(keyBytes, out _);
                return ecdh;
            }
            catch (CryptographicException)
            {
                ecdh.Dispose();
                throw new CryptographicRequestException(
                    "The supplied key is not a valid elliptic-curve private key. Expected PKCS#8, Base64 encoded.");
            }
        }

        /// <summary>Imports an ECDSA public key in X.509 SubjectPublicKeyInfo form.</summary>
        internal static ECDsa ImportEcdsaPublicKey(byte[] keyBytes)
        {
            var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                return ecdsa;
            }
            catch (CryptographicException)
            {
                ecdsa.Dispose();
                throw new CryptographicRequestException(
                    "The supplied key is not a valid ECDSA public key. Expected SubjectPublicKeyInfo, Base64 encoded.");
            }
        }

        /// <summary>Imports an ECDSA private key in PKCS#8 form.</summary>
        internal static ECDsa ImportEcdsaPrivateKey(byte[] keyBytes)
        {
            var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportPkcs8PrivateKey(keyBytes, out _);
                return ecdsa;
            }
            catch (CryptographicException)
            {
                ecdsa.Dispose();
                throw new CryptographicRequestException(
                    "The supplied key is not a valid ECDSA private key. Expected PKCS#8, Base64 encoded.");
            }
        }

        /// <summary>Maps an elliptic-curve key size to the matching SHA-2 digest.</summary>
        internal static HashAlgorithmName HashForCurveSize(int keySizeBits) => keySizeBits switch
        {
            <= 256 => HashAlgorithmName.SHA256,
            <= 384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512
        };
    }
}
