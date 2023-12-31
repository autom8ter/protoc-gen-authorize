// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: example/example.proto

package example

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ExampleService_RequestMatch_FullMethodName  = "/authorize.ExampleService/RequestMatch"
	ExampleService_MetadataMatch_FullMethodName = "/authorize.ExampleService/MetadataMatch"
	ExampleService_AllowAll_FullMethodName      = "/authorize.ExampleService/AllowAll"
)

// ExampleServiceClient is the client API for ExampleService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ExampleServiceClient interface {
	// RequestMatch - Only super admins OR users with the admin role and access to the account id in the request will be allowed
	RequestMatch(ctx context.Context, in *Request, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// MetadataMatch - Only super admins OR users with the admin role and access to the account id in the metadata will be allowed
	MetadataMatch(ctx context.Context, in *Request, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// AllowAll is an example of how to configure a method to allow all requests
	AllowAll(ctx context.Context, in *Request, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type exampleServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewExampleServiceClient(cc grpc.ClientConnInterface) ExampleServiceClient {
	return &exampleServiceClient{cc}
}

func (c *exampleServiceClient) RequestMatch(ctx context.Context, in *Request, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ExampleService_RequestMatch_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *exampleServiceClient) MetadataMatch(ctx context.Context, in *Request, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ExampleService_MetadataMatch_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *exampleServiceClient) AllowAll(ctx context.Context, in *Request, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ExampleService_AllowAll_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExampleServiceServer is the server API for ExampleService service.
// All implementations must embed UnimplementedExampleServiceServer
// for forward compatibility
type ExampleServiceServer interface {
	// RequestMatch - Only super admins OR users with the admin role and access to the account id in the request will be allowed
	RequestMatch(context.Context, *Request) (*emptypb.Empty, error)
	// MetadataMatch - Only super admins OR users with the admin role and access to the account id in the metadata will be allowed
	MetadataMatch(context.Context, *Request) (*emptypb.Empty, error)
	// AllowAll is an example of how to configure a method to allow all requests
	AllowAll(context.Context, *Request) (*emptypb.Empty, error)
	mustEmbedUnimplementedExampleServiceServer()
}

// UnimplementedExampleServiceServer must be embedded to have forward compatible implementations.
type UnimplementedExampleServiceServer struct {
}

func (UnimplementedExampleServiceServer) RequestMatch(context.Context, *Request) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestMatch not implemented")
}
func (UnimplementedExampleServiceServer) MetadataMatch(context.Context, *Request) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MetadataMatch not implemented")
}
func (UnimplementedExampleServiceServer) AllowAll(context.Context, *Request) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllowAll not implemented")
}
func (UnimplementedExampleServiceServer) mustEmbedUnimplementedExampleServiceServer() {}

// UnsafeExampleServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ExampleServiceServer will
// result in compilation errors.
type UnsafeExampleServiceServer interface {
	mustEmbedUnimplementedExampleServiceServer()
}

func RegisterExampleServiceServer(s grpc.ServiceRegistrar, srv ExampleServiceServer) {
	s.RegisterService(&ExampleService_ServiceDesc, srv)
}

func _ExampleService_RequestMatch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).RequestMatch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExampleService_RequestMatch_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).RequestMatch(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExampleService_MetadataMatch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).MetadataMatch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExampleService_MetadataMatch_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).MetadataMatch(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExampleService_AllowAll_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).AllowAll(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExampleService_AllowAll_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).AllowAll(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

// ExampleService_ServiceDesc is the grpc.ServiceDesc for ExampleService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ExampleService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "authorize.ExampleService",
	HandlerType: (*ExampleServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RequestMatch",
			Handler:    _ExampleService_RequestMatch_Handler,
		},
		{
			MethodName: "MetadataMatch",
			Handler:    _ExampleService_MetadataMatch_Handler,
		},
		{
			MethodName: "AllowAll",
			Handler:    _ExampleService_AllowAll_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "example/example.proto",
}
