# protoc-gen-authorize 🛡️

**protoc-gen-authorize** is an innovative protoc plugin and library 🌟 designed to simplify and secure gRPC request authorization. 
It seamlessly integrates authorization rules directly within your proto files 📝, reducing the need to clutter your application code with complex authorization logic. 
Perfect for developers 👨‍💻👩‍💻 looking to streamline their security workflows in gRPC applications. 
In this README, you'll find easy installation instructions 📥, examples 💡, and all you need to harness the power of expression-based rules for robust and efficient request handling 💼.


## Installation

The plugin can be installed with the following command:

```bash
    go install github.com/autom8ter/protoc-gen-authorize
```

The interceptor library can be installed with the following command:

```bash
    go get github.com/autom8ter/protoc-gen-authorize/authorizer
```

## Code Generation

The plugin generates a function `NewJavascriptAuthorizer` with rules configured for each service method in the proto file 
that has the `authorize.rules` option set. 
The function returns a `JavascriptAuthorizer` that can be used with the interceptors in `github.com/autom8ter/protoc-gen-authorize/authorizer`

The authorizer plugin can generate code with buf or protoc and requires code generation for the grpc golang plugin.

buf.gen.yaml example:

```yaml
version: v1
managed:
  enabled: true
  go_package_prefix:
    default: github.com/autom8ter/protoc-gen-authorize/gen
plugins:
  - plugin: buf.build/protocolbuffers/go
    out: gen
    opt: paths=source_relative
  - plugin: buf.build/grpc/go
    out: gen
    opt:
      - paths=source_relative
  - plugin: authorize
    out: gen
    opt:
      - paths=source_relative
```

## Example

See [example](example) for the full example.

```protobuf

// Example service is an example of how to use the authorize rules
service ExampleService {
  // ExampleMethod1 is an example of how to use the authorize rules
  rpc ExampleMethod1(Request) returns (google.protobuf.Empty){
    option (authorize.rules) = {
      // Allow if the user has access to the account id in the request and has the admin role OR if the user is a super admin
      rules: [
        {
          expression: "user.AccountIds.includes(request.AccountId) && user.Roles.includes('admin')",
        },
        {
          expression: "user.IsSuperAdmin",
        }
      ]
    };
  }
  // ExampleMethod2 is another example of how to use the authorize rules
  rpc ExampleMethod2(Request) returns (google.protobuf.Empty){
    option (authorize.rules) = {
      // Allow if the user has access to the account id in the metadata(x-account-id) and has the admin role OR if the user is a super admin
      rules: [
        {
          expression: "user.AccountIds.includes(metadata['x-account-id']) && user.Roles.includes('admin')",
        },
        {
          expression: "user.IsSuperAdmin",
        }
      ]
    };
  }
}
```

make sure to import "github.com/autom8ter/protoc-gen-authorize/authorizer" in your server code and use the authorizer interceptors:
```go
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
```

## Performance

The default authorizer for the plugin uses goja, a JavaScript interpreter written in Go.
Most benchmarks show that most rule evaluations take < .05 ms to complete.
