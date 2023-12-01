# protoc-gen-authorize 🛡️

![GoDoc](https://godoc.org/github.com/autom8ter/protoc-gen-authorize?status.svg)

**protoc-gen-authorize** is an innovative protoc plugin and library 🌟 designed to simplify and secure gRPC request
authorization.
It seamlessly integrates authorization rules directly within your proto files 📝, reducing the need to clutter your
application code with complex authorization logic.
Perfect for developers 👨‍💻👩‍💻 looking to streamline their security workflows in gRPC applications.
In this README, you'll find easy installation instructions 📥, examples 💡, and all you need to harness the power of
expression-based rules for robust and efficient request handling 💼.

## Features

- [x] Javascript or [CEL](https://github.com/google/cel-go) expression-based rules
- [x] Unary and Stream interceptors
- [x] Protoc plugin for code generation
- [x] Go library for authorizer creation along with interceptors
- [x] Injection of `request`, `metadata` and `user` variables into rules
- [x] Automatic user extraction from metadata with `userExtractor` option

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

The plugin generates a function `NewAuthorizer` with rules configured for each service method in the proto file
that has the `authorize.rules` option set.
The function returns an `Authorizer` implementation that can be used with the interceptors
in `github.com/autom8ter/protoc-gen-authorize/authorizer` (https://pkg.go.dev/github.com/autom8ter/protoc-gen-authorize@v0.4.0/authorizer)
The language the authorizer is generated in can be configured with the `authorizer` option in the plugin configuration (
CEL and javascript are supported).

The authorizer plugin can generate code with buf or protoc and requires code generation for the grpc golang plugin.

buf.gen.yaml example:

```yaml
version: v1
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
      - authorizer=javascript
#      - authorizer=cel <- enable this option to use CEL instead of javascript
```

## Example

See [example](example) for the full example.

Javascript authorizer example:

```protobuf

// Example service is an example of how to use the authorize rules
service ExampleService {
  // RequestMatch - Only super admins OR users with the admin role and access to the account id in the request will be allowed
  rpc RequestMatch(Request) returns (google.protobuf.Empty){
    option (authorize.rules) = {
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
  // MetadataMatch - Only super admins OR users with the admin role and access to the account id in the metadata will be allowed
  rpc MetadataMatch(Request) returns (google.protobuf.Empty){
    option (authorize.rules) = {
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
  // AllowAll is an example of how to configure a method to allow all requests (a single rule with a wildcard expression)
  rpc AllowAll(Request) returns (google.protobuf.Empty){
    option (authorize.rules) = {
      rules: [
        {
          expression: "*",
        }
      ]
    };
  }
}
```

## Performance

The javascript authorizer for the plugin uses goja, a JavaScript interpreter written in Go.
Most benchmarks show that most rule evaluations take < .05 ms to complete.

The [CEL](github.com/google/cel-go) authorizer for the plugin uses cel-go, a CEL interpreter written in Go.
Most benchmarks show that most rule evaluations take < .02 ms to complete.

Use whichever authorizer you prefer, but CEL is recommended for performance.

## Helpful Links

- [Javascript Authorizer Docs](https://pkg.go.dev/github.com/autom8ter/protoc-gen-authorize/authorizer/javascript)
- [CEL Authorizer Docs](https://pkg.go.dev/github.com/autom8ter/protoc-gen-authorize/authorizer/cel)
