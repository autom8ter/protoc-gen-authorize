package main

import (
	`context`
	`testing`
	`time`

	`google.golang.org/grpc`

	`github.com/autom8ter/protoc-gen-authorize/example/gen/example`
)

func Test(t *testing.T) {
	go func() {
		if err := runServer(); err != nil {
			panic(err)
		}
	}()
	// wait for server to start
	time.Sleep(1 * time.Second)
	conn, err := grpc.Dial(":10042", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	client := example.NewExampleServiceClient(conn)

	if _, err := client.ExampleMethod1(context.Background(), &example.Request{
		StrValue: "hello",
	}); err != nil {
		t.Fatalf("failed to call ExampleMethod1: %v", err)
	}
}
