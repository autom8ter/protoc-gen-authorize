package main

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"

	"github.com/autom8ter/protoc-gen-authorize/authorizer"
	"github.com/autom8ter/protoc-gen-authorize/example/gen/example"
	"github.com/autom8ter/protoc-gen-authorize/example/server"
)

var testUser = &example.User{
	Id:           "123",
	Email:        "autom8ter@protoc-gen-authorizer.com",
	Name:         "Autom8ter",
	AccountIds:   []string{"940298", "123123"},
	Roles:        []string{"admin", "user"},
	IsSuperAdmin: false,
}

// userExtractor is a function that extracts a user from a context
// in a real application, this would be a database lookup based on metadata extracted from the context
func userExtractor(ctx context.Context) (any, error) {
	return testUser, nil
}

func runServer() error {
	// create a new javascript authorizer from the generated javascript authorizer(protoc-gen-authorize)
	jsAuthorizer, err := example.NewJavascriptAuthorizer()
	if err != nil {
		return err
	}
	// create a new grpc server with the authorizer interceptors
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(
			authorizer.UnaryServerInterceptor(jsAuthorizer, authorizer.WithUserExtractor(userExtractor)),
		),
		grpc.StreamInterceptor(
			authorizer.StreamServerInterceptor(jsAuthorizer, authorizer.WithUserExtractor(userExtractor)),
		),
	)
	// register the example service
	example.RegisterExampleServiceServer(srv, server.NewExampleServer())
	lis, err := net.Listen("tcp", ":10042")
	if err != nil {
		return err
	}
	defer lis.Close()
	fmt.Println("starting server on :10042")
	// start the server
	if err := srv.Serve(lis); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := runServer(); err != nil {
		panic(err)
	}
}
