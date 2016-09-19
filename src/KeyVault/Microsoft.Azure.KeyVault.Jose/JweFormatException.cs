//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;

namespace Microsoft.Azure.KeyVault.Jose
{
    public class JweFormatException : Exception
    {
        public JweFormatException() : base( "Bad JWE Serialization value" )
        {
        }

        public JweFormatException( string message ): base( message )
        {
        }
    }
}