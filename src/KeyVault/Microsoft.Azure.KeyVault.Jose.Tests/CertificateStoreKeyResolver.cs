//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;

namespace Microsoft.Azure.KeyVault.Jose.Tests
{
    public class CertificateStoreKeyResolver : IKeyResolver
    {
        X509Store _store;

        /// <summary>
        /// Create a new Key Vault KeyResolver that uses the specified KeyVaultClient
        /// </summary>
        public CertificateStoreKeyResolver( StoreName storeName, StoreLocation storeLocation )
        {
            _store = new X509Store( storeName, storeLocation );

            // TODO: Close the store
            _store.Open( OpenFlags.ReadOnly );
        }

        #region IKeyResolver

        // Warning 1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread.
#pragma warning disable 1998

        public async Task<IKey> ResolveKeyAsync( string kid, CancellationToken token )
        {
            if ( string.IsNullOrWhiteSpace( kid ) )
                throw new ArgumentNullException( "kid" );

            var collection  = _store.Certificates.Find( X509FindType.FindByThumbprint, kid, false );
            var certificate = collection.Cast<X509Certificate2>().FirstOrDefault();

            if ( certificate != null )
            {
                return new CertificateKey( kid, certificate );
            }

            return null;
        }

#pragma warning restore 1998

        #endregion
    }
}
