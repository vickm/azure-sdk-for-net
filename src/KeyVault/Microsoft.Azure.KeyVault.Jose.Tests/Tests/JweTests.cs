//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;
using Microsoft.Azure.KeyVault.Cryptography.Algorithms;
using Xunit;

namespace Microsoft.Azure.KeyVault.Jose.Tests
{
    public class JweTests
    {
        static RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        [Fact]
        public async Task DirectMode()
        {
            // Create a Symmetric key wrapper for the key material and add it to the resolver
            var key      = new SymmetricKey("RandomAesKey", 512 >> 3);
            var resolver = new SimpleKeyResolver();

            resolver.Add( key );

            await VerifyEncryptionAndDecryptionAsync( key, resolver ).ConfigureAwait( false );
        }

        [Fact]
        public async Task DirectModeCompatibility()
        {
            // Create a key resolver and add the key
            var resolver = new SimpleKeyResolver();
            resolver.Add( WellKnownAesKey );

            // Unprotect well known jwe.
            var recovered = await JsonWebEncryption.UnprotectCompactAsync( resolver, WellKnowDirectJwe ).ConfigureAwait( false );

            // Verify if recovered text matches well known plain text.
            Assert.True( recovered.SequenceEqual( WellKnownPlaintext ) );
        }

        [Fact]
        public async Task KeyEncryptionModeCompatibility()
        {
            // Create a key resolver and add the key
            var resolver = new SimpleKeyResolver();
            resolver.Add( WellKnownRsaKey );

            // Unprotect well known jwe.
            var recovered = await JsonWebEncryption.UnprotectCompactAsync( resolver, WellKnownWrappingJwe ).ConfigureAwait( false );

            // Verify if recovered text matches well known plain text.
            Assert.True( recovered.SequenceEqual( WellKnownPlaintext ) );
        }

        [Fact]
        public async Task KeyEncryptionMode_Explicit()
        {
            // Create some plaintext
            var plaintext = new byte[256];
            _rng.GetBytes( plaintext );

            // Create the DEK (more bytes than we need)
            var dek = new byte[512 >> 3];
            _rng.GetBytes( dek );

            // Protect the plain text with assymetric key.
            var jwe = await JsonWebEncryption.ProtectCompactAsync( WellKnownRsaKey, RsaOaep.AlgorithmName, dek, Aes128CbcHmacSha256.AlgorithmName, plaintext );

            // Create a key resolver and add the key.
            var resolver = new SimpleKeyResolver();
            resolver.Add( WellKnownRsaKey );
            var recoveredtext = await JsonWebEncryption.UnprotectCompactAsync( resolver, jwe ).ConfigureAwait( false );

            // Verify recovered text is correct.
            Assert.True( plaintext.SequenceEqual( recoveredtext ) );
        }

        [Fact]
        public async Task KeyEncryptionMode_Implicit()
        {
            // Create some plaintext
            var plaintext = new byte[256];
            _rng.GetBytes( plaintext );

            // Protect the plain text with asymmetric key.
            var jwe = await JsonWebEncryption.ProtectCompactAsync( WellKnownRsaKey, RsaOaep.AlgorithmName, Aes128CbcHmacSha256.AlgorithmName, plaintext );

            // Create a key resolver and add the key.
            var resolver = new SimpleKeyResolver();
            resolver.Add( WellKnownRsaKey );
            var recoveredtext = await JsonWebEncryption.UnprotectCompactAsync( resolver, jwe ).ConfigureAwait( false );

            // Verify recovered text is correct.
            Assert.True( plaintext.SequenceEqual( recoveredtext ) );
        }

        [Fact]
        public async Task KeyWrappingMode_Explicit()
        {
            // Create some plaintext
            var plaintext = new byte[256];
            _rng.GetBytes( plaintext );

            // Create the DEK (more bytes than we need)
            var dek = new byte[512 >> 3];
            _rng.GetBytes( dek );

            // Protect the plain text with assymetric key.
            var jwe = await JsonWebEncryption.ProtectCompactAsync( WellKnownAesKey, WellKnownAesKey.DefaultKeyWrapAlgorithm, dek, Aes128CbcHmacSha256.AlgorithmName, plaintext );

            // Create a key resolver and add the key.
            var resolver = new SimpleKeyResolver();
            resolver.Add( WellKnownAesKey );
            var recoveredtext = await JsonWebEncryption.UnprotectCompactAsync( resolver, jwe ).ConfigureAwait( false );

            // Verify recovered text is correct.
            Assert.True( plaintext.SequenceEqual( recoveredtext ) );
        }

        [Fact]
        public async Task KeyWrappingMode_Implicit()
        {
            // Create some plaintext
            var plaintext = new byte[256];
            _rng.GetBytes( plaintext );

            // Protect the plain text with asymmetric key.
            var jwe = await JsonWebEncryption.ProtectCompactAsync( WellKnownAesKey, WellKnownAesKey.DefaultKeyWrapAlgorithm, Aes128CbcHmacSha256.AlgorithmName, plaintext );

            // Create a key resolver and add the key.
            var resolver = new SimpleKeyResolver();
            resolver.Add( WellKnownAesKey );
            var recoveredtext = await JsonWebEncryption.UnprotectCompactAsync( resolver, jwe ).ConfigureAwait( false );

            // Verify recovered text is correct.
            Assert.True( plaintext.SequenceEqual( recoveredtext ) );
        }

        [Fact]
        public async Task KeyNotFound()
        {
            // Create a key that will not be found, and protects some content with it.
            var key = new SymmetricKey( "Unknown", 512 >> 3 );
            var jwe = await ProtectRandomContentAsync( key ).ConfigureAwait( false );

            // Create an empty resolver.
            var resolver = new SimpleKeyResolver();

            // Try to unprotect, and verify the correct exception is thrown.
            try
            {
                await JsonWebEncryption.UnprotectCompactAsync( resolver, jwe.Item1 ).ConfigureAwait( false );
            }
            catch ( JweKeyNotFoundException ex )
            {
                
                Assert.Equal( "The resolver was unable to resolve key with Kid=\"Unknown\"", ex.Message );
            }
        }

        /*
        /// <summary>
        /// JSON serialization of SymmetricKey is not supported.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task TestSerialization()
        {
            var key1 = CreateRandomKey( "ToBeSerialized" );
            var serializedData = JsonConvert.SerializeObject( key1 );
            var key2 = JsonConvert.DeserializeObject<SymmetricKey>( serializedData );
            //Assert.Equal( key1.Kid, key2.Kid );

            //
            // Encrypt with key1 and decrypt with key2 to verify that they are the same
            //
            var resolver = new KeyResolver();
            resolver.Add( key2 );
            await VerifyEncryptionAndDecryptionAsync( key1, resolver );
        }
        */

        private static async Task VerifyEncryptionAndDecryptionAsync(IKey encryptionKey, IKeyResolver keyResolver)
        {
            var result = await ProtectRandomContentAsync( encryptionKey ).ConfigureAwait( false );
            var jwe = result.Item1;
            var plaintext = result.Item2;

            // Decrypt with keyResolver
            var recovered = await JsonWebEncryption.UnprotectCompactAsync( keyResolver, jwe ).ConfigureAwait( false );

            Assert.True( plaintext.SequenceEqual( recovered ) );
        }

        private static async Task<Tuple<string, byte[]>> ProtectRandomContentAsync(IKey encryptionKey)
        {
            // Create some plaintext
            var plaintext = new byte[256];
            new Random().NextBytes(plaintext);

            // Protect the plain text with encryptionKey
            var jwe = await JsonWebEncryption.ProtectCompactAsync( encryptionKey, Aes128CbcHmacSha256.AlgorithmName, plaintext ).ConfigureAwait( false );
            return Tuple.Create(jwe, plaintext);
        }

        [Fact]
        public async Task KeyVault_Jose_TestMalformedJwe()
        {
            // Smoke tests.
            await VerifyMalformedJweAsync( " " ).ConfigureAwait( false );
            await VerifyMalformedJweAsync( "...." ).ConfigureAwait( false );
            await VerifyMalformedJweAsync( "0.0.0.0.0" ).ConfigureAwait( false );

            // Elaborated attacks.
            var result = await CreateRandomJweAsync().ConfigureAwait( false );
            var jwe    = result.Item1;
            var key    = result.Item2;

            var keyResolver = new SimpleKeyResolver();
            keyResolver.Add( key );

            await VerifyMalformedJweAsync( jwe + " " ).ConfigureAwait( false );
            await VerifyMalformedJweAsync( " " + jwe ).ConfigureAwait( false );

            var components = jwe.Split( '.' );

            for ( var i = 0; i < components.Length; ++i )
            {
                var component = components[i];
                var prefix = i == 0 ? "" : string.Join( ".", components.Take( i ) ) + ".";
                var suffix = i + 1 == components.Length ? "" : "." + string.Join( ".", components.Skip( i + 1 ) );

                // Sanity check.
                await JsonWebEncryption.UnprotectCompactAsync( keyResolver, jwe ).ConfigureAwait( false );

                // Prepended component.
                await VerifyMalformedJweAsync( component + "." + jwe ).ConfigureAwait( false );
                // Appended component.
                await VerifyMalformedJweAsync( jwe + "." + component ).ConfigureAwait( false );

                if ( component != "" )
                {
                    // Empty component.
                    await VerifyMalformedJweAsync( prefix + suffix ).ConfigureAwait( false );

                    await VerifyMalformedJweAsync( prefix + component.Insert( 1, " " ) + suffix ).ConfigureAwait( false );
                    await VerifyMalformedJweAsync( prefix + component.Insert( component.Length - 1, " " ) + suffix ).ConfigureAwait( false );

                    // Truncated component
                    await VerifyMalformedJweAsync( prefix + component.Remove( 1 ) + suffix ).ConfigureAwait( false );
                    await VerifyMalformedJweAsync( prefix + component.Remove( component.Length - 1 ) + " " + suffix ).ConfigureAwait( false );
                }

                try
                {
                    // Prepended data on component.
                    await VerifyMalformedJweAsync( prefix + " " + component + suffix ).ConfigureAwait( false );
                    // Appended data on component.
                    await VerifyMalformedJweAsync( prefix + component + " " + suffix ).ConfigureAwait( false );

                    // Replaced by random base64url string.
                    await VerifyMalformedJweAsync( prefix + CreateRandomBase64Url() + suffix ).ConfigureAwait( false );

                    if ( i > 0 )
                    {
                        // Replaced by previous component.
                        await VerifyMalformedJweAsync( prefix + components[i - 1] + suffix ).ConfigureAwait( false );
                    }
                    if ( i + 1 < components.Length )
                    {
                        // Replaced by next component.
                        await VerifyMalformedJweAsync( prefix + components[i + 1] + suffix ).ConfigureAwait( false );
                    }
                }
                catch ( JweKeyNotFoundException )
                {
                    // The replaced component was the key id, so we are fine.
                }
            }
        }

        private async Task VerifyMalformedJweAsync( string jwe )
        {
            try
            {
                await JsonWebEncryption.UnprotectCompactAsync( new SimpleKeyResolver(), jwe ).ConfigureAwait( false );
                Assert.True( false );
            }
            catch ( JweFormatException ex )
            {
                if ( ex.Message == "Bad JWE Serialization value" )
                    return; // Ok.
                Assert.True( false, "Unexpected exception message: " + ex.Message );
            }
        }

        private static async Task<Tuple<string, SymmetricKey>> CreateRandomJweAsync( )
        {
            // Create random key.
            var key = new SymmetricKey( "123", 512 >> 3 );

            // Create some plaintext
            var plaintext = new byte[256];
            new Random().NextBytes( plaintext );

            // Protect the plain text with a random key
            var jwe = await JsonWebEncryption.ProtectCompactAsync( key, Aes128CbcHmacSha256.AlgorithmName, plaintext ).ConfigureAwait( false );
            return new Tuple<string, SymmetricKey>( jwe, key );
        }

        private static string CreateRandomBase64Url()
        {
            // Create some plaintext
            var plaintext = new byte[256];
            new Random().NextBytes( plaintext );

            return Base64UrlEncoding.ToBase64UrlString( plaintext );
        }

        private static readonly SymmetricKey WellKnownAesKey = new SymmetricKey( "AesKey", Base64UrlEncoding.FromBase64UrlString( "h4ENmjbpqdjVBl9fRhMf_zuAJakPzOQYOoVDpH37RSYjrXq5IbQi9L1_GXKiUF2Lzz8z-EilADCGjiE9rspSMQ" ) );

        private static readonly RsaKey WellKnownRsaKey = new RsaKey( "RsaKey", new RSAParameters
        {
            Modulus  = Base64UrlEncoding.FromBase64UrlString( "rjUVYtYojQ82Txub6gdNgyAMTcsRI_8X2wBFAh5WI5k-LFoSWd1B3QI2nPdMV3xSi5_3deStxGWGxdUPghWkG-3tuIduaOv7vimzES8Fnpw9qboV_TTpkBE0M6Sl8RvjH5KAb0POaggpllgEjBFZagxQBQcShXvO7E5SXb9CZI8" ),
            Exponent = Base64UrlEncoding.FromBase64UrlString( "AQAB" ),
            D        = Base64UrlEncoding.FromBase64UrlString( "LRfIhWDx9jFt2WRII3fodHyjMq_RrAOn5SRYuIepvGU6Vrip72D6X37nLBJHTI39v-6UW4vp_uBY1nSkIwP_Cl3disG43PR4veSXF3P6pl30xHioeCpCIzGd_ghlc71DElIQOuAp_Sm_jA8XHOUFjzYnwq_oqDfEKYPJKdJ936E" ),
            DP       = Base64UrlEncoding.FromBase64UrlString( "T4WTyBKr-RUipbI-g5vD2udgUi6-bxU_BQvcYxh4_12U_SsNMhbcuELmMKw09XmFDThNB_275m-9i92Lxd0vLQ" ),
            DQ       = Base64UrlEncoding.FromBase64UrlString( "rV4T92UizgZd-GnFIw-iycDM24jo7ajqSkJuCuTTonT6gGxXM7QygbngOZztrMQbxnYrr7DEmTxcwRlja7IcQQ" ),
            InverseQ = Base64UrlEncoding.FromBase64UrlString( "lmxHQPAKU09LBenM9WtSon6S7dlqYxg1yODoRUot0_zqG8HYOynaXAE9Sp7e-HJa61PP5vyclQvwEQeC1ktzag" ),
            P        = Base64UrlEncoding.FromBase64UrlString( "6O6T2P0MbExh-YLf0uY_6_2oMK-SIiOKIR9vi85vWao8Zg_RGflCMUmB85_cgPSEtghPRcIfCEHEf3OsSN9nEw" ),
            Q        = Base64UrlEncoding.FromBase64UrlString( "v3Wv488-9ggO50E27WKExLnnIvMcvb9cgJKRapTNtwM7GwRP7UZ_Xq5-h_WtoWEmWjgfoxUAQA5QMRnDsoNQFQ" ),
        } );

        private static readonly byte[] WellKnownPlaintext   = Base64UrlEncoding.FromBase64UrlString( "zoheWn0Z3EMcg_ZHqf_SGPQvtK18GY4itKYNZt1Ejp11H33udzNRvanXBZgiDVbmCZVxYLlOorX5O6XWC3Vl2PRY0omB46DA3vYEpRP2AKZQJlxI0i3jJn3I9TuNerEzcS2jyTvMZCX0sILCSf2hAjr-huQYHQXGdasMue5kM2RF0TPmUjdrg8E3UyGrINx_JvIBjvPNGlQn3VOPv6s2j30efXjKu7ADkwIi4cnkGlTOjJL8Y6RweLbfvnXj28MWAMSjjaJktWtC_fvxqjmKQ8L-wDMYOivZrQXB6v06ILc-DOAFQI2yatcmuWWpfs19VHqz5BqQ_caYyuCdospuCA" );

        private static readonly string WellKnowDirectJwe    = "eyJraWQiOiJBZXNLZXkiLCJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..p-4iqT9TidXt-ID83uLPiA.ycGsKhG0JhTynQstIhC3dBw4SiNOQkIZPUo5AHUqgWqIbYZBqBy_Gz3iCHXrEuhQMXju0Mj_jy1CXjMFWAW68ZE4sgDn6ECLYKAg6SyzkfwANM9JoMGoJLnWBxmfk84vddJvkvwEu1pKqxat96f-CMPAZ3jf7jNM0AmV2wr-FlF6rUq52SfIARY3jwgMdFBP7lT5fuUyo96UVJk5H9S0Iazt3bUBOCojCfPPw0RppPSMelC_yIEomMSEBtuTzVpql39WWZ6MOj0ikwp7MtVZPtLtV5JJmZ32SPyP2Ubzba_eUC5E5ZSiuWBT3y7Hfr3QIu-eoIcstLF8u6aXLTiuME8Fzp3bCH8F2R4OVWRIm1g.UTObOmuGQHLgTlgYD19CSg";

        private static readonly string WellKnownWrappingJwe = "eyJraWQiOiJSc2FLZXkiLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.XPn_ZrQx7G7JgNrNqrZTnOcVg7lQr4MhBPNLF3ohUuvPUh5rsDiUMlGh2Ce8ZPPDRBDznvp1Ts71kousIMwWceOOxVY5AVZJjQF4MdxHM7z1qnfzg9JKU2z8ZTSWerFx71S3kI6EJGB8FR9r5TM_h7_BxsUEb1xk4kI6dnA87H0.h75cydXBhlDaZvdXwy1Ubw.8DQxRw-40ko7wrao9G189bj16BnIJdcxX59dvrRBFFzOReYpX7-Nc-DAjOQ76khuznb-AV0F-KK-uuKaXnBQD4tfO5j29_9FtZTiXDOEEDmf52fvO46Wv_wW9Dz9NFLeml124aoFgQC6S-3k66StxppN_tmBzTuCE6PSx4tA702wx3NXqHOoF4d2xGcBJmIjdBnd8BeVRS0gQZRAvht6bcScbY92TAMBM2bXEe00C5rr-dlgvRgr4K_GTG7FrbQqm6LnCDtFKnoie2C5ILj3BkM1b9F9TwPEEbKmWnxLWLbJjocvDgXdDkW9w72iKATw-Qr5Jowb-aFl2eD5ow99xBXq9OWfmZwXttcS5p4f34o.FDRegB8g3yFscGKGAR8cmw";
    }
}