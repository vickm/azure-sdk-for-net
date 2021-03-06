// 
// Copyright (c) Microsoft and contributors.  All rights reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 
// See the License for the specific language governing permissions and
// limitations under the License.
// 

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure;
using Microsoft.Azure.Management.ApiManagement.SmapiModels;

namespace Microsoft.Azure.Management.ApiManagement
{
    /// <summary>
    /// Operations for managing Properties.
    /// </summary>
    public partial interface IPropertiesOperations
    {
        /// <summary>
        /// Creates new property.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the Api Management service.
        /// </param>
        /// <param name='propId'>
        /// Identifier of the property.
        /// </param>
        /// <param name='parameters'>
        /// Create parameters.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        Task<AzureOperationResponse> CreateAsync(string resourceGroupName, string serviceName, string propId, PropertyCreateParameters parameters, CancellationToken cancellationToken);
        
        /// <summary>
        /// Deletes specific property from the the Api Management service
        /// instance.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the Api Management service.
        /// </param>
        /// <param name='propId'>
        /// Identifier of the property.
        /// </param>
        /// <param name='etag'>
        /// ETag.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        Task<AzureOperationResponse> DeleteAsync(string resourceGroupName, string serviceName, string propId, string etag, CancellationToken cancellationToken);
        
        /// <summary>
        /// Gets specific property.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the Api Management service.
        /// </param>
        /// <param name='propId'>
        /// Identifier of the property.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// Get Property operation response details.
        /// </returns>
        Task<PropertyGetResponse> GetAsync(string resourceGroupName, string serviceName, string propId, CancellationToken cancellationToken);
        
        /// <summary>
        /// List all properties.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the Api Management service.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// List Properties operation response details.
        /// </returns>
        Task<PropertiesListResponse> ListAsync(string resourceGroupName, string serviceName, QueryParameters query, CancellationToken cancellationToken);
        
        /// <summary>
        /// List next properties page.
        /// </summary>
        /// <param name='nextLink'>
        /// NextLink from the previous successful call to List operation.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// List Properties operation response details.
        /// </returns>
        Task<PropertiesListResponse> ListNextAsync(string nextLink, CancellationToken cancellationToken);
        
        /// <summary>
        /// Patches specific property.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the Api Management service.
        /// </param>
        /// <param name='propId'>
        /// Identifier of the property.
        /// </param>
        /// <param name='parameters'>
        /// Update parameters.
        /// </param>
        /// <param name='etag'>
        /// ETag.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// A standard service response including an HTTP status code and
        /// request ID.
        /// </returns>
        Task<AzureOperationResponse> UpdateAsync(string resourceGroupName, string serviceName, string propId, PropertyUpdateParameters parameters, string etag, CancellationToken cancellationToken);
    }
}
