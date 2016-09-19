//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;

namespace Microsoft.Azure.KeyVault.Jose
{
    /// <summary>
    /// Contains the functionalities to handle base 64 URL encoding 
    /// </summary>
    public static class Base64UrlEncoding
    {
        /// <summary>
        /// Converts a byte array to a Base64Url encoded string
        /// </summary>
        /// <param name="input">The byte array to convert</param>
        /// <returns>The Base64Url encoded form of the input</returns>
        public static string ToBase64UrlString( byte[] input )
        {
            if ( input == null )
                throw new ArgumentNullException( "input" );

            return Convert.ToBase64String( input ).TrimEnd( '=' ).Replace( '+', '-' ).Replace( '/', '_' );
        }

        /// <summary>
        /// Converts a Base64Url encoded string to a byte array
        /// </summary>
        /// <param name="input">The Base64Url encoded string</param>
        /// <returns>The byte array represented by the enconded string</returns>
        public static byte[] FromBase64UrlString( string input )
        {
            if ( string.IsNullOrEmpty( input ) )
                throw new ArgumentNullException( "input" );

            return Convert.FromBase64String( Pad( input.Replace( '-', '+' ).Replace( '_', '/' ) ) );
        }

        /// <summary>
        /// Adds padding to the input
        /// </summary>
        /// <param name="input"> the input string </param>
        /// <returns> the padded string </returns>
        private static string Pad( string input )
        {
            var count = 3 - ( ( input.Length + 3 ) % 4 );

            if ( count == 0 )
            {
                return input;
            }

            return input + new string( '=', count );
        }
    }
}