package main

import (
	`fmt`
	`net`

	`google.golang.org/grpc`

	`github.com/autom8ter/protoc-gen-authorize/authorizer`
	`github.com/autom8ter/protoc-gen-authorize/example/gen/example`
	`github.com/autom8ter/protoc-gen-authorize/example/server`
	`github.com/autom8ter/protoc-gen-authorize/jsauthorizer`
)

func runServer(opts ...jsauthorizer.Opt) error {
	// create a new javascript authorizer
	jsAuth, err := jsauthorizer.New()
	if err != nil {
		return err
	}
	// create a new grpc server with the authorizer interceptors
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(
			authorizer.UnaryServerInterceptor(jsAuth, example.AuthorizationRules),
		),
		grpc.StreamInterceptor(
			authorizer.StreamServerInterceptor(jsAuth, example.AuthorizationRules),
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
