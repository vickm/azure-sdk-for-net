//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;
using Microsoft.Azure.KeyVault.Cryptography;
using Microsoft.Azure.KeyVault.Cryptography.Algorithms;

namespace Microsoft.Azure.KeyVault.Jose.Tests
{
    /// <summary>
    /// An IKey implementation using a Certificate with a RSA key.
    /// </summary>
    public class CertificateKey : IKey, IDisposable
    {
        private X509Certificate2 _certificate;
        private RSA              _publicKey;
        private RSA              _privateKey;

        /// <summary>
        /// Key Identifier
        /// </summary>
        public string Kid { get; private set; }

        /// <summary>
        /// Constructor, creates a 2048 bit key with a GUID identifier.
        /// </summary>
        public CertificateKey( X509Certificate2 certificate ) : this( certificate.Thumbprint, certificate )
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public CertificateKey( string kid, X509Certificate2 certificate )
        {
            if ( string.IsNullOrWhiteSpace( kid ) )
                throw new ArgumentNullException( "kid" );

            if ( certificate == null )
                throw new ArgumentNullException( "certificate" );

            Kid = kid;

            // TODO: Check that this is a RSA certificate
            _certificate = certificate;

#if NET45
            _publicKey  = _certificate.PublicKey.Key as RSA;
            _privateKey = ( _certificate.HasPrivateKey ) ? _certificate.PrivateKey as RSA : null;
#elif NETSTANDARD
            _publicKey  = _certificate.GetRSAPublicKey();
            _privateKey = ( _certificate.HasPrivateKey ) ? _certificate.GetRSAPrivateKey() : null;
#else
            #error Unknown framework target
#endif
        }

        // Intentionally excluded.
        //~CertificateKey()
        //{
        //    Dispose( false );
        //}

        public void Dispose()
        {
            Dispose( true );
            GC.SuppressFinalize( this );
        }

        protected virtual void Dispose( bool disposing )
        {
            // Clean up managed resources if Dispose was called
            if ( disposing )
            {
#if NET45
                // No Dispose() on net45
                _certificate = null;
#elif NETSTANDARD
                _certificate.Dispose(); _certificate = null;
#else
                #error Unknown build framework
#endif
                _privateKey.Dispose();  _privateKey  = null;
                _publicKey.Dispose();   _publicKey   = null;
            }

            // Clean up native resources always
        }

        private bool SupportsUse( X509KeyUsageFlags use )
        {
            if ( _certificate != null && _certificate.Extensions != null )
            {
                foreach ( var extension in _certificate.Extensions )
                {
                    if ( extension is X509KeyUsageExtension )
                    {
                        var usage = extension as X509KeyUsageExtension;

                        if ( usage.KeyUsages.HasFlag(use) )
                            return true;
                        else
                            return false;
                    }
                }

                // If we get here, there there was no KeyUsage extension and so
                // all uses of the key are permitted.
                return true;
            }

            // If we get here, we have no certificate.
            return false;
        }

        /// <summary>
        /// Indicates whether the RSA key has only public key material.
        /// </summary>
        public bool PublicOnly
        {
            get
            {
                if ( _certificate == null )
                    throw new ObjectDisposedException( string.Format( CultureInfo.InvariantCulture, "RsaKey {0} is disposed", Kid ) );

                return !_certificate.HasPrivateKey;
            }
        }

#region IKey implementation

        public string DefaultEncryptionAlgorithm
        {
            get { return RsaOaep.AlgorithmName; }
        }

        public string DefaultKeyWrapAlgorithm
        {
            get { return RsaOaep.AlgorithmName; }
        }

        public string DefaultSignatureAlgorithm
        {
            get { return Rs256.AlgorithmName; }
        }
        
// Warning 1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread.
#pragma warning disable 1998

        public async Task<byte[]> DecryptAsync( byte[] ciphertext, byte[] iv, byte[] authenticationData = null, byte[] authenticationTag = null, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "Certificate {0} is disposed", Kid ) );

            if ( !_certificate.HasPrivateKey || _privateKey == null )
                throw new NotSupportedException( "Certificate does not have a private key" );

            if ( !SupportsUse( X509KeyUsageFlags.DataEncipherment ) )
                throw new NotSupportedException( "Certificate does not allow data encipherment" );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultEncryptionAlgorithm;

            if ( ciphertext == null || ciphertext.Length == 0 )
                throw new ArgumentNullException( "ciphertext" );

            if ( iv != null )
                throw new ArgumentException( "Initialization vector must be null", "iv" );

            if ( authenticationData != null )
                throw new ArgumentException( "Authentication data must be null", "authenticationData" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            // Use the key that we captured in the constructor
            using ( var encryptor = algo.CreateDecryptor( _privateKey ) )
            {
                return encryptor.TransformFinalBlock( ciphertext, 0, ciphertext.Length );
            }
        }

        public async Task<Tuple<byte[], byte[], string>> EncryptAsync( byte[] plaintext, byte[] iv = null, byte[] authenticationData = null, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "Certificate {0} is disposed", Kid ) );

            if ( !SupportsUse( X509KeyUsageFlags.DataEncipherment ) )
                throw new NotSupportedException( "Certificate does not allow data encipherment" );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultEncryptionAlgorithm;

            if ( plaintext == null || plaintext.Length == 0 )
                throw new ArgumentNullException( "plaintext" );

            if ( iv != null )
                throw new ArgumentException( "Initialization vector must be null", "iv" );

            if ( authenticationData != null )
                throw new ArgumentException( "Authentication data must be null", "authenticationData" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            // Use the key we captured in the constructor
            using ( var encryptor = algo.CreateEncryptor( _publicKey ) )
            {
                return new Tuple<byte[], byte[], string>( encryptor.TransformFinalBlock( plaintext, 0, plaintext.Length ), null, algorithm );
            }
        }

        public async Task<Tuple<byte[], string>> WrapKeyAsync( byte[] key, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( !SupportsUse( X509KeyUsageFlags.KeyEncipherment ) )
                throw new NotSupportedException( "Certificate does not allow key encipherment" );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultKeyWrapAlgorithm;

            if ( key == null || key.Length == 0 )
                throw new ArgumentNullException( "key" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            // Use the key we captured in the constructor
            using ( var encryptor = algo.CreateEncryptor( _publicKey ) )
            {
                return new Tuple<byte[], string>( encryptor.TransformFinalBlock( key, 0, key.Length ), algorithm );
            }
        }

        public async Task<byte[]> UnwrapKeyAsync( byte[] encryptedKey, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default( CancellationToken ) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( !_certificate.HasPrivateKey || _privateKey == null )
                throw new NotSupportedException( "Certificate does not have a private key" );

            if ( !SupportsUse( X509KeyUsageFlags.KeyEncipherment ) )
                throw new NotSupportedException( "Certificate does not allow key encipherment" );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultKeyWrapAlgorithm;

            if ( encryptedKey == null || encryptedKey.Length == 0 )
                throw new ArgumentNullException( "wrappedKey" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            // Use the key that we captured in the constructor
            using ( var encryptor = algo.CreateDecryptor( _privateKey ) )
            {
                return encryptor.TransformFinalBlock( encryptedKey, 0, encryptedKey.Length );
            }
        }

        public async Task<Tuple<byte[], string>> SignAsync( byte[] digest, string algorithm, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( !_certificate.HasPrivateKey || _privateKey == null )
                throw new NotSupportedException( "Certificate does not have a private key" );

            if ( !SupportsUse( X509KeyUsageFlags.DigitalSignature ) )
                throw new NotSupportedException( "Certificate does not allow signature" );

            if ( algorithm == null )
                algorithm = DefaultSignatureAlgorithm;

            if ( digest == null )
                throw new ArgumentNullException( "digest" );

            AsymmetricSignatureAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricSignatureAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            // Use the key that we captured in the constructor
            var transform = algo.CreateSignatureTransform( _privateKey );

            return new Tuple<byte[], string>( transform.Sign( digest ), algorithm );
        }

        public async Task<bool> VerifyAsync( byte[] digest, byte[] signature, string algorithm, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( !SupportsUse( X509KeyUsageFlags.DigitalSignature ) )
                throw new NotSupportedException( "Certificate does not allow signature" );

            if ( digest == null )
                throw new ArgumentNullException( "digest" );

            if ( signature == null )
                throw new ArgumentNullException( "signature" );

            if ( algorithm == null )
                algorithm = DefaultSignatureAlgorithm;

            AsymmetricSignatureAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricSignatureAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            // Use the key we captured in the constructor
            var transform = algo.CreateSignatureTransform( _publicKey );

            return transform.Verify( digest, signature );
        }

#pragma warning restore 1998

#endregion
    }
}
