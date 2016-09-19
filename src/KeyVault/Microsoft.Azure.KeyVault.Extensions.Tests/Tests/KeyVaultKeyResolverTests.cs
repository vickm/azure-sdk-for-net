// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.

using System;
using System.Security.Cryptography;
using System.Threading;
using KeyVault.TestFramework;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Test.HttpRecorder;
using Microsoft.Rest.ClientRuntime.Azure.TestFramework;
using Xunit;

namespace Microsoft.Azure.KeyVault.Extensions.Tests
{

    /// <summary>
    /// Verify Symmetric Key.
    /// </summary>
    public class KeyVaultKeyResolverTests : IClassFixture<KeyVaultTestFixture>
    {
        private KeyVaultTestFixture _fixture;

        public KeyVaultKeyResolverTests( KeyVaultTestFixture fixture )
        {
            _fixture           = fixture;
        }

        private KeyVaultClient GetKeyVaultClient()
        {
            if ( _fixture.Mode == HttpRecorderMode.Record )
            {
                HttpMockServer.Variables["VaultAddress"] = _fixture._vaultAddress;
                HttpMockServer.Variables["KeyName"] = _fixture._keyName;
                HttpMockServer.Variables["KeyVersion"] = _fixture._keyVersion;
            }
            else
            {
                _fixture._vaultAddress = HttpMockServer.Variables["VaultAddress"];
                _fixture._keyName      = HttpMockServer.Variables["KeyName"];
                _fixture._keyVersion   = HttpMockServer.Variables["KeyVersion"];
            }

            _fixture._keyIdentifier = new KeyIdentifier( _fixture._vaultAddress, _fixture._keyName, _fixture._keyVersion );

            return _fixture.CreateKeyVaultClient();
        }

        /// <summary>
        /// Test resolving a key from a key in a vault using various KeyVaultKeyResolver constructors.
        /// </summary>
        [Fact]
        public void KeyVault_KeyResolver_ResolveKey()
        {
            using (MockContext context = MockContext.Start(this.GetType().FullName))
            {
                // Arrange
                var client = GetKeyVaultClient();
                var vault = _fixture._vaultAddress;

                var key = client.CreateKeyAsync(vault, "TestKey", JsonWebKeyType.Rsa).GetAwaiter().GetResult();

                if (key != null)
                {
                    try
                    {
                        VerifyResolver(client, vault, key.KeyIdentifier.BaseIdentifier, key.KeyIdentifier.Identifier);
                    }
                    finally
                    {
                        // Delete the key
                        client.DeleteKeyAsync(vault, "TestKey").GetAwaiter().GetResult();
                    }
                }
            }
        }

        /// <summary>
        /// Test resolving a key from a 128bit secret encoded as base64 in a vault using various KeyVaultKeyResolver constructors.
        /// </summary>
        [Fact]
        public void KeyVault_KeyResolver_ResolveSecret128Base64()
        {
            using (MockContext context = MockContext.Start(this.GetType().FullName))
            {
                VerifyResolveSecretBase64(128, VerifyResolver);
            }
        }

        /// <summary>
        /// Test resolving a key from a 192bit secret encoded as base64 in a vault using various KeyVaultKeyResolver constructors.
        /// </summary>
        [Fact]
        public void KeyVault_KeyResolver_ResolveSecret192Base64()
        {
            using (MockContext context = MockContext.Start(this.GetType().FullName))
            {
                VerifyResolveSecretBase64(192, VerifyResolver);
            }
        }

        /// <summary>
        /// Test resolving a key from a 256bit secret encoded as base64 in a vault using various KeyVaultKeyResolver constructors.
        /// </summary>
        [Fact]
        public void KeyVault_KeyResolver_ResolveSecret256Base64()
        {
            using (MockContext context = MockContext.Start(this.GetType().FullName))
            {
                VerifyResolveSecretBase64(256, VerifyResolver);
            }
        }

        private void VerifyResolveSecretBase64(int secretSize,
            Action<KeyVaultClient, string, string, string> verifyResolverCallback)
        {
            // Arrange
            var client = GetKeyVaultClient();
            var vault = _fixture._vaultAddress;

            var keyBytes = new byte[secretSize >> 3];

            RandomNumberGenerator.Create().GetBytes(keyBytes);

            var secret =
                client.SetSecretAsync(vault, "TestSecret", Convert.ToBase64String(keyBytes), null,
                    "application/octet-stream").GetAwaiter().GetResult();

            if (secret != null)
            {
                try
                {
                    verifyResolverCallback(client, vault, secret.SecretIdentifier.BaseIdentifier,
                        secret.SecretIdentifier.Identifier);
                }
                finally
                {
                    // Delete the key
                    client.DeleteSecretAsync(vault, "TestSecret").GetAwaiter().GetResult();
                }
            }
        }

        private void VerifyResolver(KeyVaultClient client, string vault, string baseIdentifier, string identifier)
        {
            // ctor with client
            var resolver = new KeyVaultKeyResolver(client);

            var baseKey = resolver.ResolveKeyAsync(baseIdentifier, default(CancellationToken)).GetAwaiter().GetResult();
            var versionKey = resolver.ResolveKeyAsync(identifier, default(CancellationToken)).GetAwaiter().GetResult();

            Assert.Equal(baseKey.Kid, versionKey.Kid);

            // NOTE: ctor with authentication callback. We cannot test this ctor unless
            //       we are running in live mode as it will create a new KeyVaultClient.
            if ( _fixture.Mode == HttpRecorderMode.Record)
            {
                resolver = new KeyVaultKeyResolver(_fixture.GetAccessToken);

                baseKey = resolver.ResolveKeyAsync(baseIdentifier, default(CancellationToken)).GetAwaiter().GetResult();
                versionKey = resolver.ResolveKeyAsync(identifier, default(CancellationToken)).GetAwaiter().GetResult();

                Assert.Equal(baseKey.Kid, versionKey.Kid);
            }

            // ctor with vault name and client
            resolver = new KeyVaultKeyResolver(vault, client);

            baseKey = resolver.ResolveKeyAsync(baseIdentifier, default(CancellationToken)).GetAwaiter().GetResult();
            versionKey = resolver.ResolveKeyAsync(identifier, default(CancellationToken)).GetAwaiter().GetResult();

            Assert.Equal(baseKey.Kid, versionKey.Kid);

            // NOTE: ctor with authentication callback. We cannot test this ctor unless
            //       we are running in live mode as it will create a new KeyVaultClient.
            if ( _fixture.Mode == HttpRecorderMode.Record)
            {
                resolver = new KeyVaultKeyResolver(vault, _fixture.GetAccessToken);

                baseKey = resolver.ResolveKeyAsync(baseIdentifier, default(CancellationToken)).GetAwaiter().GetResult();
                versionKey = resolver.ResolveKeyAsync(identifier, default(CancellationToken)).GetAwaiter().GetResult();

                Assert.Equal(baseKey.Kid, versionKey.Kid);
            }

            baseKey.Dispose();
            versionKey.Dispose();
        }
    }
}
