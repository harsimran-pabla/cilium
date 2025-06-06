// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armnetwork

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// AdminRulesClient contains the methods for the AdminRules group.
// Don't use this type directly, use NewAdminRulesClient() instead.
type AdminRulesClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewAdminRulesClient creates a new instance of AdminRulesClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewAdminRulesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*AdminRulesClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &AdminRulesClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// CreateOrUpdate - Creates or updates an admin rule.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - networkManagerName - The name of the network manager.
//   - configurationName - The name of the network manager Security Configuration.
//   - ruleCollectionName - The name of the network manager security Configuration rule collection.
//   - ruleName - The name of the rule.
//   - adminRule - The admin rule to create or update
//   - options - AdminRulesClientCreateOrUpdateOptions contains the optional parameters for the AdminRulesClient.CreateOrUpdate
//     method.
func (client *AdminRulesClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, adminRule BaseAdminRuleClassification, options *AdminRulesClientCreateOrUpdateOptions) (AdminRulesClientCreateOrUpdateResponse, error) {
	var err error
	const operationName = "AdminRulesClient.CreateOrUpdate"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, networkManagerName, configurationName, ruleCollectionName, ruleName, adminRule, options)
	if err != nil {
		return AdminRulesClientCreateOrUpdateResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return AdminRulesClientCreateOrUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusCreated) {
		err = runtime.NewResponseError(httpResp)
		return AdminRulesClientCreateOrUpdateResponse{}, err
	}
	resp, err := client.createOrUpdateHandleResponse(httpResp)
	return resp, err
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *AdminRulesClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, adminRule BaseAdminRuleClassification, _ *AdminRulesClientCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkManagers/{networkManagerName}/securityAdminConfigurations/{configurationName}/ruleCollections/{ruleCollectionName}/rules/{ruleName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkManagerName == "" {
		return nil, errors.New("parameter networkManagerName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkManagerName}", url.PathEscape(networkManagerName))
	if configurationName == "" {
		return nil, errors.New("parameter configurationName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{configurationName}", url.PathEscape(configurationName))
	if ruleCollectionName == "" {
		return nil, errors.New("parameter ruleCollectionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleCollectionName}", url.PathEscape(ruleCollectionName))
	if ruleName == "" {
		return nil, errors.New("parameter ruleName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleName}", url.PathEscape(ruleName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	if err := runtime.MarshalAsJSON(req, adminRule); err != nil {
		return nil, err
	}
	return req, nil
}

// createOrUpdateHandleResponse handles the CreateOrUpdate response.
func (client *AdminRulesClient) createOrUpdateHandleResponse(resp *http.Response) (AdminRulesClientCreateOrUpdateResponse, error) {
	result := AdminRulesClientCreateOrUpdateResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result); err != nil {
		return AdminRulesClientCreateOrUpdateResponse{}, err
	}
	return result, nil
}

// BeginDelete - Deletes an admin rule.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - networkManagerName - The name of the network manager.
//   - configurationName - The name of the network manager Security Configuration.
//   - ruleCollectionName - The name of the network manager security Configuration rule collection.
//   - ruleName - The name of the rule.
//   - options - AdminRulesClientBeginDeleteOptions contains the optional parameters for the AdminRulesClient.BeginDelete method.
func (client *AdminRulesClient) BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, options *AdminRulesClientBeginDeleteOptions) (*runtime.Poller[AdminRulesClientDeleteResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.deleteOperation(ctx, resourceGroupName, networkManagerName, configurationName, ruleCollectionName, ruleName, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[AdminRulesClientDeleteResponse]{
			FinalStateVia: runtime.FinalStateViaLocation,
			Tracer:        client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[AdminRulesClientDeleteResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// Delete - Deletes an admin rule.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
func (client *AdminRulesClient) deleteOperation(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, options *AdminRulesClientBeginDeleteOptions) (*http.Response, error) {
	var err error
	const operationName = "AdminRulesClient.BeginDelete"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, networkManagerName, configurationName, ruleCollectionName, ruleName, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusAccepted, http.StatusNoContent) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// deleteCreateRequest creates the Delete request.
func (client *AdminRulesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, options *AdminRulesClientBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkManagers/{networkManagerName}/securityAdminConfigurations/{configurationName}/ruleCollections/{ruleCollectionName}/rules/{ruleName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkManagerName == "" {
		return nil, errors.New("parameter networkManagerName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkManagerName}", url.PathEscape(networkManagerName))
	if configurationName == "" {
		return nil, errors.New("parameter configurationName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{configurationName}", url.PathEscape(configurationName))
	if ruleCollectionName == "" {
		return nil, errors.New("parameter ruleCollectionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleCollectionName}", url.PathEscape(ruleCollectionName))
	if ruleName == "" {
		return nil, errors.New("parameter ruleName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleName}", url.PathEscape(ruleName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	if options != nil && options.Force != nil {
		reqQP.Set("force", strconv.FormatBool(*options.Force))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// Get - Gets a network manager security configuration admin rule.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - networkManagerName - The name of the network manager.
//   - configurationName - The name of the network manager Security Configuration.
//   - ruleCollectionName - The name of the network manager security Configuration rule collection.
//   - ruleName - The name of the rule.
//   - options - AdminRulesClientGetOptions contains the optional parameters for the AdminRulesClient.Get method.
func (client *AdminRulesClient) Get(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, options *AdminRulesClientGetOptions) (AdminRulesClientGetResponse, error) {
	var err error
	const operationName = "AdminRulesClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, networkManagerName, configurationName, ruleCollectionName, ruleName, options)
	if err != nil {
		return AdminRulesClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return AdminRulesClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return AdminRulesClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *AdminRulesClient) getCreateRequest(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleName string, _ *AdminRulesClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkManagers/{networkManagerName}/securityAdminConfigurations/{configurationName}/ruleCollections/{ruleCollectionName}/rules/{ruleName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkManagerName == "" {
		return nil, errors.New("parameter networkManagerName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkManagerName}", url.PathEscape(networkManagerName))
	if configurationName == "" {
		return nil, errors.New("parameter configurationName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{configurationName}", url.PathEscape(configurationName))
	if ruleCollectionName == "" {
		return nil, errors.New("parameter ruleCollectionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleCollectionName}", url.PathEscape(ruleCollectionName))
	if ruleName == "" {
		return nil, errors.New("parameter ruleName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleName}", url.PathEscape(ruleName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *AdminRulesClient) getHandleResponse(resp *http.Response) (AdminRulesClientGetResponse, error) {
	result := AdminRulesClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result); err != nil {
		return AdminRulesClientGetResponse{}, err
	}
	return result, nil
}

// NewListPager - List all network manager security configuration admin rules.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - networkManagerName - The name of the network manager.
//   - configurationName - The name of the network manager Security Configuration.
//   - ruleCollectionName - The name of the network manager security Configuration rule collection.
//   - options - AdminRulesClientListOptions contains the optional parameters for the AdminRulesClient.NewListPager method.
func (client *AdminRulesClient) NewListPager(resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, options *AdminRulesClientListOptions) *runtime.Pager[AdminRulesClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[AdminRulesClientListResponse]{
		More: func(page AdminRulesClientListResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *AdminRulesClientListResponse) (AdminRulesClientListResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "AdminRulesClient.NewListPager")
			nextLink := ""
			if page != nil {
				nextLink = *page.NextLink
			}
			resp, err := runtime.FetcherForNextLink(ctx, client.internal.Pipeline(), nextLink, func(ctx context.Context) (*policy.Request, error) {
				return client.listCreateRequest(ctx, resourceGroupName, networkManagerName, configurationName, ruleCollectionName, options)
			}, nil)
			if err != nil {
				return AdminRulesClientListResponse{}, err
			}
			return client.listHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listCreateRequest creates the List request.
func (client *AdminRulesClient) listCreateRequest(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, options *AdminRulesClientListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkManagers/{networkManagerName}/securityAdminConfigurations/{configurationName}/ruleCollections/{ruleCollectionName}/rules"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkManagerName == "" {
		return nil, errors.New("parameter networkManagerName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkManagerName}", url.PathEscape(networkManagerName))
	if configurationName == "" {
		return nil, errors.New("parameter configurationName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{configurationName}", url.PathEscape(configurationName))
	if ruleCollectionName == "" {
		return nil, errors.New("parameter ruleCollectionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{ruleCollectionName}", url.PathEscape(ruleCollectionName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	if options != nil && options.SkipToken != nil {
		reqQP.Set("$skipToken", *options.SkipToken)
	}
	if options != nil && options.Top != nil {
		reqQP.Set("$top", strconv.FormatInt(int64(*options.Top), 10))
	}
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// listHandleResponse handles the List response.
func (client *AdminRulesClient) listHandleResponse(resp *http.Response) (AdminRulesClientListResponse, error) {
	result := AdminRulesClientListResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.AdminRuleListResult); err != nil {
		return AdminRulesClientListResponse{}, err
	}
	return result, nil
}
