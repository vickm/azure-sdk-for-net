// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.

namespace Microsoft.Azure.KeyVault.Cryptography.Algorithms
{
    /// <summary>
    /// JWA none: https://tools.ietf.org/html/rfc7518#section-3.6
    /// </summary>
    public class None : Algorithm
    {
        public const string AlgorithmName = "none";

        public None()
            : base(AlgorithmName)
        {
        }
    }
}
