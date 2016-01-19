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

using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Microsoft.KeyVault.Jose
{
    [DataContract()]
    public class EncryptedData
    {
        [DataMember( Name = "recipients", IsRequired = true, EmitDefaultValue = false )]
        public WrappedKey[] Recipients;

        [DataMember( Name = "enc", IsRequired = true, EmitDefaultValue = false )]
        public string Encryption { get; set; }

        [DataMember( Name = "iv", IsRequired = true, EmitDefaultValue = false )]
        public byte[] IV { get; set; }

        [DataMember( Name = "ciphertext", IsRequired = true, EmitDefaultValue = false )]
        public byte[] CipherText { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject( this );
        }
    }
}
