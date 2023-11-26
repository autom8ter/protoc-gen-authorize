# protoc-gen-authorize

A protoc plugin and library for authorizing gRPC requests using
expression based rules. It allows developers to specify authorization
rules in the proto file itself, instead of in the application code.

## Installation

The plugin can be installed with the following command:
```bash
    go install github.com/autom8ter/protoc-gen-authorize
```

## Example

```protobuf

service ExampleService {
  rpc ExampleMethod1(Request) returns (google.protobuf.Empty){
    option (authorize.rules) = {
      // allow if request.StrValue == 'hello'
      rules: [
        {
          expression: "request.StrValue == 'hello'",
        },
        // allow if request.IntValue == 1
        {
          expression: "request.IntValue == 1",
        },
        // allow if request.BoolValue == true
        {
          expression: "request.BoolValue == true",
        },
        // allow if request.DoubleValue == 1.0
        {
          expression: "request.DoubleValue == 1.0",
        },
        // allow if request.FloatValue == 1.0
        {
          expression: "request.FloatValue == 1.0",
        },
        // allow if request.StructValue == {key: 'value'}
        {
          expression: "request.StructValue == {key: 'value'}",
        },
        // allow if request.StrArray == ['hello', 'world']
        {
          expression: "request.StrArray == ['hello', 'world']",
        },
        // allow if request.IntArray == [1, 2]
        {
          expression: "request.IntArray == [1, 2]",
        },
        // allow if request.BoolArray == [true, false]
        {
          expression: "request.BoolArray == [true, false]",
        },
        // allow if request.FloatArray == [1.0, 2.0]
        {
          expression: "request.FloatArray == [1.0, 2.0]",
        },
        // allow if request.DoubleArray == [1.0, 2.0]
        {
          expression: "request.DoubleArray == [1.0, 2.0]",
        },
        {
          expression: "request.StructValue == {key: 'value'}",
        }
      ]
    };
  }
}

```

See [example](example) for the full example.