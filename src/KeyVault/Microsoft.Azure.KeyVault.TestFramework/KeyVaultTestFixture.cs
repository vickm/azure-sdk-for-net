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
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.Graph.RBAC;
using Microsoft.Azure.Graph.RBAC.Models;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Test.HttpRecorder;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.ClientRuntime.Azure.TestFramework;
using Microsoft.Azure.Management.ResourceManager;

namespace KeyVault.TestFramework
{
    public class KeyVaultTestFixture : IDisposable
    {
        // Required in test code
        public string           _vaultAddress;
        public bool             _standardVaultOnly;

        public string           _keyName;
        public string           _keyVersion;
        public KeyIdentifier    _keyIdentifier;

        public ClientCredential _clientCredential;

        public HttpRecorderMode Mode;

        // Required for cleaning up at the end of the test
        private string rgName = "", appObjectId = "";
        private bool fromConfig;

        public KeyVaultTestFixture()
        {
            Initialize( this.GetType().FullName );

            if ( Mode == HttpRecorderMode.Record )
            {
                // Create one key to use for testing. Key creation is expensive.
                var client     = new KeyVaultClient(new TestKeyVaultCredential(GetAccessToken), GetHandlers());

                var attributes = new KeyAttributes();
                var createdKey = Task.Run( () => client.CreateKeyAsync( _vaultAddress,
                                                                        _keyName,
                                                                        JsonWebKeyType.Rsa,
                                                                        2048,
                                                                        JsonWebKeyOperation.AllOperations,
                                                                        attributes ) ).ConfigureAwait( false ).GetAwaiter().GetResult();
                _keyIdentifier = new KeyIdentifier( createdKey.Key.Kid );
                _keyVersion    = _keyIdentifier.Version;
            }
        }

        public void Initialize( string className )
        {
            HttpMockServer.FileSystemUtilsObject = new FileSystemUtils();

            Mode = HttpMockServer.GetCurrentMode();

            if ( Mode == HttpRecorderMode.Record )
            {
                // Obtain target settings from configuration if this is record mode.
                fromConfig = LoadConfiguration();

                if ( !fromConfig ) throw new InvalidOperationException( "Configuration for record mode was not loaded" );

                // Boot the mock http server
                HttpMockServer.Initialize( className, "InitialCreation", HttpRecorderMode.Record );
                HttpMockServer.CreateInstance();
            }
        }

        private static string GetKeyVaultLocation(ResourceManagementClient resourcesClient)
        {
            var providers = resourcesClient.Providers.Get("Microsoft.KeyVault");
            var location = providers.ResourceTypes.Where(
                (resType) =>
                {
                    if (resType.ResourceType == "vaults")
                        return true;
                    else
                        return false;
                }
                ).First().Locations.FirstOrDefault();
            return location;
        }

        private static ServicePrincipal CreateServicePrincipal(Application app,
            GraphRbacManagementClient graphClient)
        {
            var parameters = new ServicePrincipalCreateParameters
            {
                AccountEnabled = true,
                AppId = app.AppId
            };
            var servicePrincipal = graphClient.ServicePrincipal.Create(parameters);
            return servicePrincipal;
        }

        private static Application CreateApplication(GraphRbacManagementClient graphClient, string appDisplayName, string secret)
        {
            return graphClient.Application.Create(new ApplicationCreateParameters
            {
                DisplayName = appDisplayName,
                IdentifierUris = new List<string>() { "http://" + Guid.NewGuid().ToString() + ".com" },
                Homepage = "http://contoso.com",
                AvailableToOtherTenants = false,
                PasswordCredentials = new[]
                {
                    new PasswordCredential
                    {
                        Value = secret,
                        StartDate = DateTime.Now - TimeSpan.FromDays(1),
                        EndDate = DateTime.Now + TimeSpan.FromDays(1),
                        KeyId = Guid.NewGuid().ToString()
                    }
                }
            });
        }

        private bool LoadConfiguration()
        {
            string vault                   = TestConfigurationManager.TryGetEnvironmentOrAppSetting("VaultUrl");
            string client_id               = TestConfigurationManager.TryGetEnvironmentOrAppSetting("AuthClientId");
            string client_secret           = TestConfigurationManager.TryGetEnvironmentOrAppSetting("AuthClientSecret");
            string standardVaultOnlyString = TestConfigurationManager.TryGetEnvironmentOrAppSetting("StandardVaultOnly");
            string keyName                 = TestConfigurationManager.TryGetEnvironmentOrAppSetting("KeyName");

            bool standardVaultOnly;

            if ( !bool.TryParse( standardVaultOnlyString, out standardVaultOnly ) )
            {
                standardVaultOnly = false;
            }

            if ( string.IsNullOrWhiteSpace( vault ) || string.IsNullOrWhiteSpace( client_id ) || string.IsNullOrWhiteSpace( client_secret ) )
            {
                return false;
            }
            else
            {
                if ( string.IsNullOrWhiteSpace( keyName ) ) keyName = "AzureSDKTestKey";

                _vaultAddress      = vault;
                _keyName           = keyName;
                _clientCredential  = new ClientCredential( client_id, client_secret );
                _standardVaultOnly = standardVaultOnly;

                return true;
            }
        }
        
        public async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, _clientCredential).ConfigureAwait(false);

            return result.AccessToken;
        }

        public KeyVaultClient CreateKeyVaultClient()
        {
            var myclient = new KeyVaultClient(new TestKeyVaultCredential(GetAccessToken), GetHandlers());
            return myclient;
        }

        public DelegatingHandler[] GetHandlers()
        {
            HttpMockServer server = HttpMockServer.CreateInstance();
            var testHttpHandler = new TestHttpMessageHandler();
            return new DelegatingHandler[] { server, testHttpHandler };
        }

        public void Dispose()
        {
            if ( Mode == HttpRecorderMode.Record && !fromConfig )
            {
                var testEnv = TestEnvironmentFactory.GetTestEnvironment();
                using ( var context = new MockContext() )
                {

                    var resourcesClient = context.GetServiceClient<ResourceManagementClient>();
                    var graphClient     = context.GetServiceClient<GraphRbacManagementClient>();

                    graphClient.TenantID = testEnv.Tenant;
                    graphClient.BaseUri = new Uri( "https://graph.windows.net" );

                    graphClient.Application.Delete( appObjectId );
                    resourcesClient.ResourceGroups.Delete( rgName );
                }
            }
        }
    }
}
