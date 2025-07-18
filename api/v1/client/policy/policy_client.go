// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new policy API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new policy API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new policy API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for policy API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteFqdnCache(params *DeleteFqdnCacheParams, opts ...ClientOption) (*DeleteFqdnCacheOK, error)

	DeletePolicy(params *DeletePolicyParams, opts ...ClientOption) (*DeletePolicyOK, error)

	GetFqdnCache(params *GetFqdnCacheParams, opts ...ClientOption) (*GetFqdnCacheOK, error)

	GetFqdnCacheID(params *GetFqdnCacheIDParams, opts ...ClientOption) (*GetFqdnCacheIDOK, error)

	GetFqdnNames(params *GetFqdnNamesParams, opts ...ClientOption) (*GetFqdnNamesOK, error)

	GetIP(params *GetIPParams, opts ...ClientOption) (*GetIPOK, error)

	GetIdentity(params *GetIdentityParams, opts ...ClientOption) (*GetIdentityOK, error)

	GetIdentityEndpoints(params *GetIdentityEndpointsParams, opts ...ClientOption) (*GetIdentityEndpointsOK, error)

	GetIdentityID(params *GetIdentityIDParams, opts ...ClientOption) (*GetIdentityIDOK, error)

	GetPolicy(params *GetPolicyParams, opts ...ClientOption) (*GetPolicyOK, error)

	GetPolicySelectors(params *GetPolicySelectorsParams, opts ...ClientOption) (*GetPolicySelectorsOK, error)

	PutPolicy(params *PutPolicyParams, opts ...ClientOption) (*PutPolicyOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	DeleteFqdnCache deletes matching DNS lookups from the policy generation cache

	Deletes matching DNS lookups from the cache, optionally restricted by

DNS name. The removed IP data will no longer be used in generated
policies.
*/
func (a *Client) DeleteFqdnCache(params *DeleteFqdnCacheParams, opts ...ClientOption) (*DeleteFqdnCacheOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteFqdnCacheParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteFqdnCache",
		Method:             "DELETE",
		PathPattern:        "/fqdn/cache",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &DeleteFqdnCacheReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteFqdnCacheOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteFqdnCache: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeletePolicy deletes a policy sub tree

Deprecated: will be removed in v1.19
*/
func (a *Client) DeletePolicy(params *DeletePolicyParams, opts ...ClientOption) (*DeletePolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeletePolicyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeletePolicy",
		Method:             "DELETE",
		PathPattern:        "/policy",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &DeletePolicyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeletePolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeletePolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetFqdnCache retrieves the list of DNS lookups intercepted from all endpoints

	Retrieves the list of DNS lookups intercepted from endpoints,

optionally filtered by DNS name, CIDR IP range or source.
*/
func (a *Client) GetFqdnCache(params *GetFqdnCacheParams, opts ...ClientOption) (*GetFqdnCacheOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFqdnCacheParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetFqdnCache",
		Method:             "GET",
		PathPattern:        "/fqdn/cache",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetFqdnCacheReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetFqdnCacheOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetFqdnCache: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetFqdnCacheID retrieves the list of DNS lookups intercepted from an endpoint

	Retrieves the list of DNS lookups intercepted from the specific endpoint,

optionally filtered by endpoint id, DNS name, CIDR IP range or source.
*/
func (a *Client) GetFqdnCacheID(params *GetFqdnCacheIDParams, opts ...ClientOption) (*GetFqdnCacheIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFqdnCacheIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetFqdnCacheID",
		Method:             "GET",
		PathPattern:        "/fqdn/cache/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetFqdnCacheIDReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetFqdnCacheIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetFqdnCacheID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetFqdnNames lists internal DNS selector representations

	Retrieves the list of DNS-related fields (names to poll, selectors and

their corresponding regexes).
*/
func (a *Client) GetFqdnNames(params *GetFqdnNamesParams, opts ...ClientOption) (*GetFqdnNamesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFqdnNamesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetFqdnNames",
		Method:             "GET",
		PathPattern:        "/fqdn/names",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetFqdnNamesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetFqdnNamesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetFqdnNames: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetIP lists information about known IP addresses

	Retrieves a list of IPs with known associated information such as

their identities, host addresses, Kubernetes pod names, etc.
The list can optionally filtered by a CIDR IP range.
*/
func (a *Client) GetIP(params *GetIPParams, opts ...ClientOption) (*GetIPOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIPParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetIP",
		Method:             "GET",
		PathPattern:        "/ip",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetIPReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIPOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetIP: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetIdentity retrieves a list of identities that have metadata matching the provided parameters

Retrieves a list of identities that have metadata matching the provided parameters, or all identities if no parameters are provided.
*/
func (a *Client) GetIdentity(params *GetIdentityParams, opts ...ClientOption) (*GetIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetIdentity",
		Method:             "GET",
		PathPattern:        "/identity",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetIdentityReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetIdentityEndpoints retrieves identities which are being used by local endpoints
*/
func (a *Client) GetIdentityEndpoints(params *GetIdentityEndpointsParams, opts ...ClientOption) (*GetIdentityEndpointsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityEndpointsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetIdentityEndpoints",
		Method:             "GET",
		PathPattern:        "/identity/endpoints",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetIdentityEndpointsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityEndpointsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetIdentityEndpoints: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetIdentityID retrieves identity
*/
func (a *Client) GetIdentityID(params *GetIdentityIDParams, opts ...ClientOption) (*GetIdentityIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetIdentityID",
		Method:             "GET",
		PathPattern:        "/identity/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetIdentityIDReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetIdentityID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetPolicy retrieves entire policy tree

	Returns the entire policy tree with all children.

Deprecated: will be removed in v1.19
*/
func (a *Client) GetPolicy(params *GetPolicyParams, opts ...ClientOption) (*GetPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPolicyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetPolicy",
		Method:             "GET",
		PathPattern:        "/policy",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetPolicyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetPolicySelectors sees what selectors match which identities
*/
func (a *Client) GetPolicySelectors(params *GetPolicySelectorsParams, opts ...ClientOption) (*GetPolicySelectorsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPolicySelectorsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetPolicySelectors",
		Method:             "GET",
		PathPattern:        "/policy/selectors",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetPolicySelectorsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetPolicySelectorsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetPolicySelectors: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PutPolicy creates or update a policy sub tree

Deprecated: will be removed in v1.19
*/
func (a *Client) PutPolicy(params *PutPolicyParams, opts ...ClientOption) (*PutPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPutPolicyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PutPolicy",
		Method:             "PUT",
		PathPattern:        "/policy",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PutPolicyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PutPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PutPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
