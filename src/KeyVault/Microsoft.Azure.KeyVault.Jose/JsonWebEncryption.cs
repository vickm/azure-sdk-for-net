//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault.Jose
{
    public static class JsonWebEncryption
    {
        private const string DirectAlgorithm = "dir";

        private static readonly RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();

        /// <summary>
        /// Protects the specified plaintext using the provided key in Direct Key Management Mode.
        /// </summary>
        /// <param name="dataEncryptionKey">The data encryption key</param>
        /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
        /// <param name="plaintext">The data to protect</param>
        /// <returns>A Flattened JWE object</returns>
        public static async Task<JweObject> ProtectAsync( IKey dataEncryptionKey, string dataEncryptionAlgorithm, byte[] plaintext )
        {
            if ( dataEncryptionKey == null )
                throw new ArgumentNullException( "dataEncryptionKey" );

            if ( dataEncryptionAlgorithm == null )
                throw new ArgumentNullException( "dataEncryptionAlgorithm" );

            if ( plaintext == null )
                throw new ArgumentNullException( "plaintext" );

            // Create protected header specifying encryption parameters.
            string    protectedHeader;
            byte[]    authenticationData;

            var unprotectedHeader = CreateHeader( DirectAlgorithm, dataEncryptionAlgorithm, dataEncryptionKey.Kid, out protectedHeader, out authenticationData );

            // In Direct Encryption mode, the content encryption key is the key provided
            // by the caller and there is no wrapped key in the output. The provided must
            // be a symmetric encryption key.

            // Encrypt the plaintext
            var iv              = GenerateIv();
            var encryptedResult = await dataEncryptionKey.EncryptAsync( plaintext, iv, authenticationData, dataEncryptionAlgorithm, default( CancellationToken ) ).ConfigureAwait( false );

            return CreateJwe( protectedHeader, unprotectedHeader, null, encryptedResult.Item1, iv, encryptedResult.Item2 );
        }

        /// <summary>
        /// Protects the specified plaintext using the provided key encryption key. A randomly generated 
        /// data encryption key is used to encrypt the plaintext and then is protected using the key
        /// encryption key.
        /// </summary>
        /// <param name="keyEncryptionKey">The key encryption key</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
        /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
        /// <param name="plaintext">The data to protect</param>
        /// <returns>A compressed form JSON Web Encryption object</returns>
        public static Task<JweObject> ProtectAsync( IKey keyEncryptionKey, string keyEncryptionAlgorithm, string dataEncryptionAlgorithm, byte[] plaintext )
        {
            // Generate sufficient key material for any of the possible algorithms
            var keyMaterial = new byte[512 >> 3];

            _rng.GetNonZeroBytes( keyMaterial );

            return ProtectAsync( keyEncryptionKey, keyEncryptionAlgorithm, keyMaterial, dataEncryptionAlgorithm, plaintext );
        }


        /// <summary>
        /// Protects the specified plaintext using the provided key encryption and data encryption keys.
        /// The keyEncryptionAlgorithm defines how the content encryption key (CEK) is protected and the
        /// dataEncryptionAlgorithm defines how the plaintext is encrypted.
        /// </summary>
        /// <param name="keyEncryptionKey">The root protection key</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
        /// <param name="dataEncryptionKey">The data encryption key</param>
        /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
        /// <param name="plaintext">The data to protect</param>
        /// <returns>A Flattened JWE object</returns>
        public static async Task<JweObject> ProtectAsync( IKey keyEncryptionKey, string keyEncryptionAlgorithm, byte[] dataEncryptionKey, string dataEncryptionAlgorithm, byte[] plaintext )
        {
            if ( keyEncryptionKey == null )
                throw new ArgumentNullException( "keyEncryptionKey" );

            if ( keyEncryptionAlgorithm == null )
                throw new ArgumentNullException( "keyEncryptionAlgorithm" );

            if ( dataEncryptionKey == null )
                throw new ArgumentNullException( "dataEncryptionKey" );

            if ( dataEncryptionAlgorithm == null )
                throw new ArgumentNullException( "dataEncryptionAlgorithm" );

            if ( plaintext == null )
                throw new ArgumentNullException( "plaintext" );

            // Create protected header specifying encryption parameters.
            string    protectedHeader;
            byte[]    authenticationData;

            var unprotectedHeader = CreateHeader( keyEncryptionAlgorithm, dataEncryptionAlgorithm, keyEncryptionKey.Kid, out protectedHeader, out authenticationData );

            // In Key Wrapping mode, the key encryption key is used to
            // protect the data encryption key and the encrypted key
            // is carried in the final package.
            var wrapKeyResult = await keyEncryptionKey.WrapKeyAsync( dataEncryptionKey, keyEncryptionAlgorithm, default( CancellationToken ) ).ConfigureAwait( false );
            var wrappedKey    = wrapKeyResult.Item1;

            // Encrypt the plaintext
            var iv              = GenerateIv();
            var encryptedResult = await new SymmetricKey( "cek", dataEncryptionKey ).EncryptAsync( plaintext, iv, authenticationData, dataEncryptionAlgorithm ).ConfigureAwait( false );

            return CreateJwe( protectedHeader, unprotectedHeader, wrappedKey, encryptedResult.Item1, iv, encryptedResult.Item2 );
        }

        /// <summary>
        /// Protects the specified plaintext using the provided key in Direct Key Management Mode.
        /// </summary>
        /// <param name="dataEncryptionKey">The data encryption key</param>
        /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
        /// <param name="plaintext">The data to protect</param>
        /// <returns>A compressed form JSON Web Encryption object</returns>
        public static async Task<string> ProtectCompactAsync( IKey dataEncryptionKey, string dataEncryptionAlgorithm, byte[] plaintext )
        {
            return ( await ProtectAsync( dataEncryptionKey, dataEncryptionAlgorithm, plaintext ).ConfigureAwait( false ) ).ToCompactJwe();
        }

        /// <summary>
        /// Protects the specified plaintext using the provided key encryption key. A randomly generated 
        /// data encryption key is used to encrypt the plaintext and then is protected using the key
        /// encryption key.
        /// </summary>
        /// <param name="keyEncryptionKey">The key encryption key</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
        /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
        /// <param name="plaintext">The data to protect</param>
        /// <returns>A compressed form JSON Web Encryption object</returns>
        public static async Task<string> ProtectCompactAsync( IKey keyEncryptionKey, string keyEncryptionAlgorithm, string dataEncryptionAlgorithm, byte[] plaintext )
        {
            return ( await ProtectAsync( keyEncryptionKey, keyEncryptionAlgorithm, dataEncryptionAlgorithm, plaintext ).ConfigureAwait( false ) ).ToCompactJwe();
        }

        /// <summary>
        /// Protects the specified plaintext using the provided key encryption and data encryption keys.
        /// The keyEncryptionAlgorithm defines how the content encryption key (CEK) is protected and the
        /// dataEncryptionAlgorithm defines how the plaintext is encrypted.
        /// </summary>
        /// <param name="keyEncryptionKey">The root protection key</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm</param>
        /// <param name="dataEncryptionKey">The data encryption key</param>
        /// <param name="dataEncryptionAlgorithm">The data encryption algorithm</param>
        /// <param name="plaintext">The data to protect</param>
        /// <returns>A compressed form JSON Web Encryption object</returns>
        public static async Task<string> ProtectCompactAsync( IKey keyEncryptionKey, string keyEncryptionAlgorithm, byte[] dataEncryptionKey, string dataEncryptionAlgorithm, byte[] plaintext )
        {
            return ( await ProtectAsync( keyEncryptionKey, keyEncryptionAlgorithm, dataEncryptionKey, dataEncryptionAlgorithm, plaintext ).ConfigureAwait( false ) ).ToCompactJwe();
        }

        public static async Task<byte[]> UnprotectAsync( IKeyResolver keyResolver, JweObject jwe )
        {
            if ( keyResolver == null )
                throw new ArgumentNullException( "keyResolver" );

            if ( jwe == null )
                throw new ArgumentNullException( "jwe" );

            string    protectedHeaderEncoded;
            JweHeader protectedHeader;
            string    encryptedKeyEncoded;
            byte[] iv;
            byte[] ciphertext;
            byte[] authenticationTag;

            try
            {
                // Deserialize the header. For security, we ignore jwe.Unprotected.
                protectedHeaderEncoded = jwe.Protected;
                protectedHeader        = JweHeader.FromCompactHeader( protectedHeaderEncoded );

                // Extract other values.
                encryptedKeyEncoded = jwe.EncryptedKey;
                iv                  = Base64UrlEncoding.FromBase64UrlString( jwe.Iv );
                ciphertext          = Base64UrlEncoding.FromBase64UrlString( jwe.Ciphertext );
                authenticationTag   = Base64UrlEncoding.FromBase64UrlString( jwe.Tag );
            }
            catch ( FormatException /* Property is not Base64Url. */)
            {
                throw new JweFormatException();
            }
            catch ( ArgumentException /* Property is empty string or null. */ )
            {
                throw new JweFormatException();
            }

            if ( protectedHeader == null ||
                 string.IsNullOrEmpty( protectedHeader.KeyWrapAlgorithm ) ||
                 string.IsNullOrEmpty( protectedHeader.EncryptionAlgorithm ) ||
                 string.IsNullOrEmpty( protectedHeader.Kid ) )
                throw new JweFormatException();

            // Step 1: Resolve the protection key
            var baseKey = await keyResolver.ResolveKeyAsync( protectedHeader.Kid, default( CancellationToken ) ).ConfigureAwait( false );

            if ( baseKey == null )
                throw new JweKeyNotFoundException( string.Format( CultureInfo.InvariantCulture, "The resolver was unable to resolve key with Kid=\"{0}\"", protectedHeader.Kid ) );

            // Step 2: Unwrap the CEK according to the specified Key Management Mode
            IKey dataEncryptionKey;

            switch ( protectedHeader.KeyWrapAlgorithm.ToLowerInvariant() )
            {
                case DirectAlgorithm:
                    {
                        // Direct Encryption
                        if ( !string.IsNullOrEmpty( encryptedKeyEncoded ) )
                            throw new JweFormatException( "Bad JWE value: uses direct encryption, but contains wrapped key." );

                        dataEncryptionKey = baseKey;
                    }
                    break;

                default:
                    {
                        // Some form of Key Wrapping algorithm
                        if ( string.IsNullOrEmpty( encryptedKeyEncoded ) )
                            throw new JweFormatException( "Bad JWE value: algorithm requires wrapped key, but one was not informed." );

                        var encryptedKey = Base64UrlEncoding.FromBase64UrlString( encryptedKeyEncoded );

                        var dataEncryptionKeyBytes = await baseKey.UnwrapKeyAsync( encryptedKey, protectedHeader.KeyWrapAlgorithm, default( CancellationToken ) ).ConfigureAwait( false );

                        if ( dataEncryptionKeyBytes == null )
                            throw new CryptographicException( "Unable to unwrap encryption key" );

                        dataEncryptionKey = new SymmetricKey( "cek", dataEncryptionKeyBytes );
                    }
                    break;
            }

            // Step 2: Decrypt
            return await dataEncryptionKey.DecryptAsync( ciphertext, iv, Encoding.ASCII.GetBytes( protectedHeaderEncoded ), authenticationTag, protectedHeader.EncryptionAlgorithm, default( CancellationToken ) ).ConfigureAwait( false );
        }

        public static Task<byte[]> UnprotectCompactAsync( IKeyResolver keyResolver, string compactJwe )
        {
            if ( keyResolver == null )
                throw new ArgumentNullException( "keyResolver" );

            if ( string.IsNullOrEmpty( compactJwe ) )
                throw new ArgumentNullException( "compactJwe" );

            var jwe = JweObject.FromCompactJwe( compactJwe, false );

            return UnprotectAsync( keyResolver, jwe );
        }

        private static byte[] GenerateIv()
        {
            var iv = new byte[16];
            _rng.GetBytes( iv );
            return iv;
        }

        private static JweHeader CreateHeader( string keyWrapAlgorithm, string dataEncryptionAlgorithm, string keyIdentifier, out string protectedHeader, out byte[] authenticationData )
        {
            // Create the unprotected header
            var header = new JweHeader
            {
                Kid                 = keyIdentifier,
                KeyWrapAlgorithm    = keyWrapAlgorithm,
                EncryptionAlgorithm = dataEncryptionAlgorithm,
            };

            // Encode the protected header to Base64URL of the UTF8 bytes of the header text
            protectedHeader = header.ToCompactHeader();
            
            // The authenticated data is the ASCII bytes of the encoded protected header
            authenticationData = Encoding.ASCII.GetBytes( protectedHeader );

            return header;
        }

        private static JweObject CreateJwe( string protectedHeader, JweHeader unprotectedHeader, byte[] wrappedKey, byte[] ciphertext, byte[] iv, byte[] authenticationTag )
        {
            return new JweObject
            {
                Protected       = protectedHeader,
                Unprotected     = unprotectedHeader,
                EncryptedKey    = wrappedKey == null ? String.Empty : Base64UrlEncoding.ToBase64UrlString( wrappedKey ),
                Ciphertext      = Base64UrlEncoding.ToBase64UrlString( ciphertext ),
                Iv              = Base64UrlEncoding.ToBase64UrlString( iv ),
                Tag             = Base64UrlEncoding.ToBase64UrlString( authenticationTag ),
            };
        }

    }
}
