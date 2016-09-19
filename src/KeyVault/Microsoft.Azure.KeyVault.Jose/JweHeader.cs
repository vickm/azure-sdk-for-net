//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault.Jose
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