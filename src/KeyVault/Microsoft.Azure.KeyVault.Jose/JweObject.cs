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
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault.Jose
{
    [JsonObject]
    public class JweObject
    {
        [JsonProperty( PropertyName = "protected", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string Protected { get; set; }

        [JsonProperty( PropertyName = "unprotected", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public JweHeader Unprotected { get; set; }

        [JsonProperty( PropertyName = "encrypted_key", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string EncryptedKey { get; set; }

        [JsonProperty( PropertyName = "iv", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string Iv { get; set; }

        [JsonProperty( PropertyName = "ciphertext", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string Ciphertext { get; set; }

        [JsonProperty( PropertyName = "tag", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string Tag { get; set; }

        [JsonProperty( PropertyName = "aad", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string AuthenticationData { get; set; }

        [JsonExtensionData]
        protected Dictionary<string, object> ExtensionData { get; set; }

        public string ToCompactJwe()
        {
            if ( Protected == null || EncryptedKey == null || Iv == null || Ciphertext == null )
                throw new InvalidOperationException( "JWE object is not complete" );

            return Protected + "." + EncryptedKey + "." + Iv + "." + Ciphertext + "." + Tag;
        }

        public static JweObject FromCompactJwe( string compactJwe, bool parseProtected = true )
        {
            if ( String.IsNullOrEmpty( compactJwe ) )
                throw new ArgumentException( "jwe" );

            var components = compactJwe.Split( '.' );

            if ( components == null || components.Length != 5 )
                throw new JweFormatException();

            return new JweObject
            {
                Protected    = components[0],
                Unprotected  = parseProtected ? JweHeader.FromCompactHeader( components[0] ) : null,
                EncryptedKey = components[1],
                Iv           = components[2],
                Ciphertext   = components[3],
                Tag          = components[4],
            };
        }
    }
}