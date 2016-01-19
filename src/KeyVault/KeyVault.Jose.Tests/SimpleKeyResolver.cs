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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;

namespace KeyVault.Jose.Tests
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
