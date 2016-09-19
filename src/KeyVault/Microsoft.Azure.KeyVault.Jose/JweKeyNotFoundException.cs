//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;

namespace Microsoft.Azure.KeyVault.Jose
{
    public class JweKeyNotFoundException : Exception
    {
        public JweKeyNotFoundException( string message ): base( message )
        {
        }
    }
}