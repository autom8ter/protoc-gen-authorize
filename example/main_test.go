package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/autom8ter/protoc-gen-authorize/example/gen/example"
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

	{
		// permission denied
		if _, err := client.RequestMatch(context.Background(), &example.Request{
			AccountId: "123",
			Message:   "hello",
		}); err == nil {
			t.Fatalf("expected error, got nil")
		} else {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("expected error code %v, got %v", codes.PermissionDenied, status.Code(err))
			}
		}
	}
	{
		// authorized: user.AccountIds.includes(request.account_id) && user.Roles.includes('admin')
		if _, err := client.RequestMatch(context.Background(), &example.Request{
			AccountId: testUser.AccountIds[0],
			Message:   "hello",
		}); err != nil {
			t.Fatalf("failed to call RequestMatch: %v", err)
		}
	}
	{
		// permission denied
		if _, err := client.MetadataMatch(context.Background(), &example.Request{
			AccountId: testUser.AccountIds[0],
			Message:   "hello",
		}); err == nil {
			t.Fatalf("expected error, got nil")
		} else {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("expected error code %v, got %v", codes.PermissionDenied, status.Code(err))
			}
		}
	}
	{
		// authorized: user.AccountIds.includes(metadata['x-account-id']) && user.Roles.includes('admin')
		ctx := context.Background()
		ctx = metadata.AppendToOutgoingContext(ctx, "x-account-id", testUser.AccountIds[0])
		if _, err := client.MetadataMatch(ctx, &example.Request{
			AccountId: testUser.AccountIds[0],
			Message:   "hello",
		}); err != nil {
			t.Fatalf("failed to call MetadataMatch: %v", err)
		}
	}
	{
		// authorized: true
		if _, err := client.AllowAll(context.Background(), &example.Request{
			AccountId: testUser.AccountIds[0],
			Message:   "hello",
		}); err != nil {
			t.Fatalf("failed to call AllowAll: %v", err)
		}
	}
}
