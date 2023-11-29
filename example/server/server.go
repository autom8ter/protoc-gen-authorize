package server

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/autom8ter/protoc-gen-authorize/example/gen/example"
)

type exampleServer struct {
	example.UnimplementedExampleServiceServer
}

func NewExampleServer() example.ExampleServiceServer {
	return &exampleServer{}
}

func (e *exampleServer) RequestMatch(ctx context.Context, request *example.Request) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (e *exampleServer) MetadataMatch(ctx context.Context, request *example.Request) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (e *exampleServer) AllowAll(ctx context.Context, request *example.Request) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
