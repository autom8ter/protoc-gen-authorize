package authorizer

import (
	"context"

	`github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors`
	`github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector`
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ExpressionVar is a global variable injected into a Javascript/CEL authorization expression
type ExpressionVar string

const (
	// ExpressionVarRequest is the request object
	ExpressionVarRequest ExpressionVar = "request"
	// ExpressionVarMetadata is the metadata object
	ExpressionVarMetadata ExpressionVar = "metadata"
	// ExpressionVarUser is the user object
	ExpressionVarUser ExpressionVar = "user"
	// ExpressionVarIsStream is true if the grpc handler is a streaming handler
	ExpressionVarIsStream ExpressionVar = "is_stream"
	// ExpressionVarMethod is the grpc method
	ExpressionVarMethod ExpressionVar = "method"
)

// RuleExecutionParams is the set of parameters passed to the Authorizer.ExecuteRule function
type RuleExecutionParams struct {
	// User is the user extracted from the context using the Authorizer.ExtractUser function
	User any
	// Request is the request object passed to the grpc handler
	Request any
	// Metadata is the metadata passed to the grpc handler
	Metadata metadata.MD
	// IsStream is true if the grpc handler is a streaming handler
	IsStream bool
}

// UserExtractor is a function that extracts a user from a context so it's attributes can be used in rule expression evaluation
type UserExtractor func(ctx context.Context) (any, error)

type ctxKey string

// DefaultUserExtractorKey is the default key used to extract a user from the context
var DefaultUserExtractorKey ctxKey = "user"

// DefaultUserExtractor is the default user extractor function that extracts a user from the context using the DefaultUserExtractorKey
func DefaultUserExtractor(ctx context.Context) (any, error) {
	user := ctx.Value(DefaultUserExtractorKey)
	if user == nil {
		return nil, status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
	return user, nil
}

// AuthorizeMethodFunc is a function that authorizes a grpc request
type AuthorizeMethodFunc func(ctx context.Context, method string, params *RuleExecutionParams) (allow bool, err error)

// AuthorizeMethod implements the Authorizer interface
func (f AuthorizeMethodFunc) AuthorizeMethod(ctx context.Context, method string, params *RuleExecutionParams) (allow bool, err error) {
	return f(ctx, method, params)
}

// Authorizer is an interface for authorizing grpc requests
type Authorizer interface {
	// AuthorizeMethod is called by the grpc interceptor to authorize a request
	AuthorizeMethod(ctx context.Context, method string, params *RuleExecutionParams) (allow bool, err error)
}

type options struct {
	userExtractor    UserExtractor
	whiteListMethods []string
	selectors        []selector.Matcher
}

// Opt is an option for configuring the interceptor
type Opt func(o *options)

// WithUserExtractor sets the user extractor function that will be used by the interceptor
// to extract a user from the context so it's attributes can be used in rule expression evaluation.
// It is injected into the expression vm as the "user" variable
func WithUserExtractor(extractor UserExtractor) Opt {
	return func(o *options) {
		o.userExtractor = extractor
	}
}

// WithWhiteListMethods sets the list of methods that will be allowed without authorization
func WithWhiteListMethods(methods []string) Opt {
	return func(o *options) {
		o.whiteListMethods = methods
	}
}

// WithSelectors sets the list of selectors that will be used to determine if the interceptor should be applied to a request
func WithSelectors(selectors ...selector.Matcher) Opt {
	return func(o *options) {
		o.selectors = append(o.selectors, selectors...)
	}
}

// UnaryServerInterceptor uses the given authorizer to authorize unary grpc requests.
// JavascriptAuthorizer/CELAuthorizer are implementations of Authorizer that use javascript/CEL expressions to authorize requests
func UnaryServerInterceptor(authorizer Authorizer, opts ...Opt) grpc.UnaryServerInterceptor {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if len(o.selectors) > 0 {
			meta := interceptors.NewServerCallMeta(info.FullMethod, nil, req)
			for _, s := range o.selectors {
				if s.Match(ctx, meta) {
					return unaryServerInterceptor(authorizer, o)(ctx, req, info, handler)
				}
			}
			return handler(ctx, req)
		}
		return unaryServerInterceptor(authorizer, o)(ctx, req, info, handler)
	}
}

func unaryServerInterceptor(authorizer Authorizer, o *options) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {

		for _, m := range o.whiteListMethods {
			if m == info.FullMethod {
				return handler(ctx, req)
			}
		}
		var (
			usr any
			err error
		)
		if o.userExtractor != nil {
			usr, err = o.userExtractor(ctx)
			if err != nil {
				return nil, err
			}
		}
		md, _ := metadata.FromIncomingContext(ctx)
		authorized, err := authorizer.AuthorizeMethod(ctx, info.FullMethod, &RuleExecutionParams{
			User:     usr,
			Request:  req,
			Metadata: md,
		})
		if err != nil {
			return nil, err
		}
		if authorized {
			return handler(ctx, req)
		}

		return nil, status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
}

// StreamServerInterceptor uses the given authorizer to authorize streaming grpc requests.
// JavascriptAuthorizer/CELAuthorizer are implementations of Authorizer that use javascript/CEL expressions to authorize requests
// the request object in the expression evaluation is nil because it is not available in the context for streaming requests
func StreamServerInterceptor(authorizer Authorizer, opts ...Opt) grpc.StreamServerInterceptor {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if len(o.selectors) > 0 {
			meta := interceptors.NewServerCallMeta(info.FullMethod, info, nil)
			for _, s := range o.selectors {
				if s.Match(ss.Context(), meta) {
					return streamServerInterceptor(authorizer, o)(srv, ss, info, handler)
				}
			}
			return handler(srv, ss)
		}
		return streamServerInterceptor(authorizer, o)(srv, ss, info, handler)
	}
}

func streamServerInterceptor(authorizer Authorizer, o *options) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		for _, m := range o.whiteListMethods {
			if m == info.FullMethod {
				return handler(srv, ss)
			}
		}
		var (
			usr any
			err error
		)
		if o.userExtractor != nil {
			usr, err = o.userExtractor(ss.Context())
			if err != nil {
				return err
			}
		}
		md, _ := metadata.FromIncomingContext(ss.Context())
		authorized, err := authorizer.AuthorizeMethod(ss.Context(), info.FullMethod, &RuleExecutionParams{
			User:     usr,
			Metadata: md,
			IsStream: true,
		})
		if err != nil {
			return err
		}
		if authorized {
			return handler(srv, ss)
		}
		return status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
}

// Chain chains multiple authorizers together - if any authorizer returns true, the request is authorized
func Chain(authz ...Authorizer) Authorizer {
	return AuthorizeMethodFunc(func(ctx context.Context, method string, params *RuleExecutionParams) (bool, error) {
		for _, a := range authz {
			allow, err := a.AuthorizeMethod(ctx, method, params)
			if err != nil {
				return false, err
			}
			if allow {
				return true, nil
			}
		}
		return false, nil
	})
}
