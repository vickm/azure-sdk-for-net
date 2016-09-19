//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;

namespace Microsoft.Azure.KeyVault.Jose.Tests
{
    internal class SimpleKeyResolver : IKeyResolver
    {
        private readonly Dictionary<string, IKey> Keys = new Dictionary<string, IKey>();

        private string _currentKey = null;

        public void Add( IKey key )
        {
            Keys[key.Kid] = key;
        }

        public void SetCurrentKey( string kid )
        {
            if ( string.IsNullOrWhiteSpace( kid ) )
                throw new ArgumentNullException( "kid" );

            if ( !Keys.ContainsKey( kid ) )
                throw new ArgumentException( "key does not exist" );

            _currentKey = kid;
        }

        public IKey GetCurrentKey()
        {
            if ( string.IsNullOrWhiteSpace( _currentKey ) )
                return null;

            return Keys[_currentKey];
        }

        public Task<IKey> GetCurrentKeyAsync()
        {
            return Task.FromResult(GetCurrentKey());
        }

        private IKey ResolveKey( string kid )
        {
            IKey value;
            if ( !Keys.TryGetValue( kid, out value ) )
                return null;
            return value;
        }

        public Task<IKey> ResolveKeyAsync( string kid, CancellationToken token )
        {
            return Task.FromResult( ResolveKey( kid ) );
        }
    }
}
