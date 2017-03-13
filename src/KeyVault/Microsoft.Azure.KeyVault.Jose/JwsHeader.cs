﻿//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

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
    [JsonObject]
    public class JwsHeader
    {
        [JsonProperty(PropertyName = "alg", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string SignatureAlgorithm;

        [JsonProperty(PropertyName = "typ", DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string JoseType;


    }
}
