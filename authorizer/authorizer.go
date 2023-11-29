package authorizer

import (
	"context"

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

// Authorizer is an interface for authorizing grpc requests
type Authorizer interface {
	// AuthorizeMethod is called by the grpc interceptor to authorize a request
	AuthorizeMethod(ctx context.Context, method string, params *RuleExecutionParams) (allow bool, err error)
}

type options struct {
	userExtractor    UserExtractor
	whiteListMethods []string
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

// UnaryServerInterceptor uses the given authorizer to authorize unary grpc requests.
// JavascriptAuthorizer/CELAuthorizer are implementations of Authorizer that use javascript/CEL expressions to authorize requests
func UnaryServerInterceptor(authorizer []Authorizer, opts ...Opt) grpc.UnaryServerInterceptor {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
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
		for _, a := range authorizer {
			authorized, err := a.AuthorizeMethod(ctx, info.FullMethod, &RuleExecutionParams{
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
		}

		return nil, status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
}

// StreamServerInterceptor uses the given authorizer to authorize streaming grpc requests.
// JavascriptAuthorizer/CELAuthorizer are implementations of Authorizer that use javascript/CEL expressions to authorize requests
// the request object in the expression evaluation is nil because it is not available in the context for streaming requests
func StreamServerInterceptor(authorizer []Authorizer, opts ...Opt) grpc.StreamServerInterceptor {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
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
		for _, a := range authorizer {
			authorized, err := a.AuthorizeMethod(ss.Context(), info.FullMethod, &RuleExecutionParams{
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
		}
		return status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
}
