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
using System.Text;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault.Express
{
    [JsonObject]
    public class JweHeader
    {
        [JsonProperty( PropertyName = "kid", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string Kid;

        [JsonProperty( PropertyName = "alg", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string KeyWrapAlgorithm;

        [JsonProperty( PropertyName = "enc", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default )]
        public string EncryptionAlgorithm;

        [JsonExtensionData]
        protected Dictionary<string, object> ExtensionData { get; set; }

        public static JweHeader FromString( string json )
        {
            return JsonConvert.DeserializeObject<JweHeader>( json );
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject( this );
        }

        public static JweHeader FromCompactHeader( string compactHeader )
        {
            try
            {
                return FromString( Encoding.UTF8.GetString( Base64UrlEncoding.FromBase64UrlString( compactHeader ) ) );
            }
            catch ( FormatException /* Not Base64Url. */ )
            {
                throw new JweFormatException();
            }
            catch ( ArgumentException /* Empty string or null. */ )
            {
                throw new JweFormatException();
            }
            catch ( JsonException /* Not valid JSON. */ )
            {
                throw new JweFormatException();
            }
        }

        public string ToCompactHeader()
        {
            return Base64UrlEncoding.ToBase64UrlString( Encoding.UTF8.GetBytes( ToString() ) );
        }
    }
}