package authorizer

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/autom8ter/protoc-gen-authorize/gen/authorize"
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

// Authorizer is an interface for authorizing grpc requests
type Authorizer interface {
	// ExtractUser extracts a user from the context so it's attributes can be used in rule expression evaluation
	ExtractUser(ctx context.Context) (any, error)
	// ExecuteRule executes a rule against the RuleExecutionParams and returns a boolean representing whether the
	// rule passed or not.
	ExecuteRule(ctx context.Context, rule *authorize.Rule, params *RuleExecutionParams) (allow bool, err error)
}

// UnaryServerInterceptor is a grpc unary middleware for authorization
func UnaryServerInterceptor(authorizer Authorizer, ruleSet map[string]*authorize.RuleSet) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		rules, ok := ruleSet[info.FullMethod]
		if !ok {
			return handler(ctx, req)
		}
		usr, err := authorizer.ExtractUser(ctx)
		if err != nil {
			return nil, err
		}
		md, _ := metadata.FromIncomingContext(ctx)
		for _, rule := range rules.Rules {
			allow, err := authorizer.ExecuteRule(ctx, rule, &RuleExecutionParams{
				User:     usr,
				Request:  req,
				Metadata: md,
			})
			if err != nil {
				return nil, err
			}
			if allow {
				return handler(ctx, req)
			}
		}
		return nil, status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
}

// StreamServerInterceptor is a grpc streaming middleware for authorization
// Request is nil because it is not available in the context for streaming requests
func StreamServerInterceptor(authorizer Authorizer, ruleSet map[string]*authorize.RuleSet) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		rules, ok := ruleSet[info.FullMethod]
		if !ok {
			return handler(srv, ss)
		}
		usr, err := authorizer.ExtractUser(ss.Context())
		if err != nil {
			return err
		}
		md, _ := metadata.FromIncomingContext(ss.Context())
		for _, rule := range rules.Rules {
			allow, err := authorizer.ExecuteRule(ss.Context(), rule, &RuleExecutionParams{
				User:     usr,
				Request:  nil,
				Metadata: md,
				IsStream: true,
			})
			if err != nil {
				return err
			}
			if allow {
				return handler(srv, ss)
			}
		}
		return status.Errorf(codes.PermissionDenied, "authorizer: permission denied")
	}
}
