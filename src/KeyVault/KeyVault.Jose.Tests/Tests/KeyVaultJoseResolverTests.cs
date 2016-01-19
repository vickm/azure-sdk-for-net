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
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Cryptography.Algorithms;
using Microsoft.Azure.KeyVault.Jose;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Test;
using Microsoft.Azure.Test.HttpRecorder;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Xunit;

namespace KeyVault.Jose.Tests
{

    /// <summary>
    /// Verify Symmetric Key.
    /// </summary>
    public class KeyVaultJoseResolverTests : IUseFixture<TestFixture>
    {
        private string                        _vaultAddress;
        private ClientCredential              _credential;
        private TokenCache                    _tokenCache;

        private static RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();

        public void SetFixture( TestFixture testFixture )
        {
            testFixture.Initialize( TestUtilities.GetCallingClass() );

            if ( HttpMockServer.Mode == HttpRecorderMode.Record )
            {
                // SECURITY: DO NOT USE IN PRODUCTION CODE; FOR TEST PURPOSES ONLY
                ServicePointManager.ServerCertificateValidationCallback += ( sender, cert, chain, sslPolicyErrors ) => true;

                _vaultAddress = testFixture.VaultAddress;
                _credential   = testFixture._ClientCredential;
                _tokenCache   = new TokenCache();

            }
        }

        private DelegatingHandler[] GetHandlers()
        {
            HttpMockServer server;

            try
            {
                server = HttpMockServer.CreateInstance();
            }
            catch ( ApplicationException )
            {
                // mock server has never been initialized, we will need to initialize it.
                HttpMockServer.Initialize( "TestEnvironment", "InitialCreation" );
                server = HttpMockServer.CreateInstance();
            }

            return new DelegatingHandler[] { server, new TestHttpMessageHandler() };
        }

        private KeyVaultClient CreateKeyVaultClient()
        {
            return new KeyVaultClient( new TestKeyVaultCredential( GetAccessToken ), GetHandlers() );
        }

        private KeyVaultClient GetKeyVaultClient()
        {
            if ( HttpMockServer.Mode == HttpRecorderMode.Record )
            {
                HttpMockServer.Variables["VaultAddress"] = _vaultAddress;
            }
            else
            {
                _vaultAddress = HttpMockServer.Variables["VaultAddress"];
            }

            return CreateKeyVaultClient();
        }

        private async Task<string> GetAccessToken( string authority, string resource, string scope )
        {
            var context = new AuthenticationContext( authority, _tokenCache );
            var result  = await context.AcquireTokenAsync( resource, _credential ).ConfigureAwait( false );

            return result.AccessToken;
        }

        /// <summary>
        /// Test resolving a key from a key in a vault using various KeyVaultKeyResolver constructors.
        /// </summary>
        [Fact]
        public void KeyVault_Jose_KeyResolverRoundTrip()
        {
            using ( var undoContext = UndoContext.Current )
            {
                undoContext.Start();

                // Arrange
                var client = GetKeyVaultClient();
                var vault  = _vaultAddress;

                var collection = new X509Certificate2Collection();

                collection.Import( Resource.PwdlessCertificate, null, X509KeyStorageFlags.Exportable );

                var certificate = collection.Cast<X509Certificate2>().FirstOrDefault();

                var secret = client.SetSecretAsync( vault, "Certificate", Convert.ToBase64String( Resource.PwdlessCertificate ), null, "application/pkcs12" ).GetAwaiter().GetResult();

                if ( secret != null )
                {
                    try
                    {
                        // ctor with client
                        var expressResolver = new ExpressCertificateResolver( client );
                        var simpleResolver  = new SimpleKeyResolver();
                        //var storeResolver   = new CertificateStoreKeyResolver( StoreName.My, StoreLocation.LocalMachine );

                        simpleResolver.Add( new CertificateKey( certificate ) );

                        var baseKey    = expressResolver.ResolveKeyAsync( secret.SecretIdentifier.BaseIdentifier, default( CancellationToken ) ).GetAwaiter().GetResult();
                        var versionKey = expressResolver.ResolveKeyAsync( secret.SecretIdentifier.Identifier, default( CancellationToken ) ).GetAwaiter().GetResult();

                        Assert.Equal( baseKey.Kid, versionKey.Kid );

                        // Create some plaintext
                        var plaintext = new byte[256];
                        _rng.GetNonZeroBytes( plaintext );

                        // Protect the plain text with assymetric key.
                        var    jwe = JsonWebEncryption.ProtectCompactAsync( baseKey, RsaOaep.AlgorithmName, Aes128CbcHmacSha256.AlgorithmName, plaintext ).GetAwaiter().GetResult();

                        byte[] x   = JsonWebEncryption.UnprotectCompactAsync( simpleResolver, jwe ).GetAwaiter().GetResult();

                        Assert.Equal( plaintext, x );
                    }
                    finally
                    {
                        // Delete the key
                        client.DeleteSecretAsync( vault, "Certificate" ).GetAwaiter().GetResult();
                    }
                }
            }
        }
    }
}
