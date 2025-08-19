# API Key Server

A simple HTTP server implemented in Rust that manages API keys associated with hex strings.

## Features

- **Generate API Keys**: Create new API keys associated with hex strings
- **Retrieve API Keys**: Look up API keys by their associated hex string
- **Rotate API Keys**: Replace existing API keys with newly generated ones
- **SQLite Storage**: Persistent storage of hex string to API key mappings

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gen-api-key` | POST | Generate a new API key for a given hex string |
| `/get-api-key` | GET | Retrieve the API key associated with a hex string |
| `/rotate-api-key` | POST | Generate a new API key and replace the existing one |

Note: The endpoints are named `/gen-api-key` but the actual handler function is called `create_api_key` to avoid Rust keyword conflicts.

## Request & Response Formats

### Generate API Key

**Request:**
```json
{
  "hex_string": "0xabcdef123456"
}
```

**Response:**
```json
{
  "api_key": "sk_...................=="
}
```

### Get API Key

**Request:**
```json
{
  "hex_string": "0xabcdef123456"
}
```

**Response:**
```json
{
  "api_key": "sk_.................=="
}
```

### Rotate API Key

**Request:**
```json
{
  "hex_string": "0xabcdef123456"
}
```

**Response:**
```json
{
  "api_key": "sk_................=="
}
```

## Input Validation

The server validates that all hex strings:
- Start with the "0x" prefix
- Contain only valid hexadecimal characters (0-9, a-f, A-F) after the prefix

## Installation and Running

1. Make sure you have Rust and Cargo installed.
2. Clone this repository.
3. Build the project:
```console
cargo build --release
```
4. Run the API key server:
```console
./target/release/api-key-generator
# The API key server will start on `127.0.0.1:8081` by default.
```
5. Start HTTP server for the users:
```console
python -m http.server 8080
```


## CORS Support

The server is configured with CORS (Cross-Origin Resource Sharing) support:
- Allows requests from any origin
- Supports all HTTP methods
- Allows all headers
- Sets a max age of 3600 seconds

This means web applications can interact with the API server even when hosted on different domains/ports.

## Error Handling

The server returns appropriate HTTP status codes and error messages:

- `400 Bad Request`: Invalid input (e.g., non-hex string, missing 0x prefix)
- `404 Not Found`: Hex string not found in database
- `500 Internal Server Error`: Database or other server errors

All errors are logged with appropriate severity levels and include detailed information to help with debugging.

## Logging

The server implements comprehensive logging for better debugging and monitoring:

- **Log Format**: `[TIMESTAMP] [LEVEL] - MESSAGE`
- **Access Logs**: Every HTTP request is logged with client IP, request details, status code, and timing
- **Validation Logs**: Input validation results are logged at DEBUG/WARN level
- **Database Logs**: Database operations success/failure are logged
- **Error Logs**: Detailed error information is logged at appropriate levels

To see more detailed logs, you can set the `RUST_LOG` environment variable:

```console
# Show all logs (including debug)
RUST_LOG=debug ./target/release/apikey_server

# Show only info and above (default)
RUST_LOG=info ./target/release/apikey_server

# Show only warnings and errors
RUST_LOG=warn ./target/release/apikey_server
```

Example log output:
```console
[2025-04-23 14:32:15] [INFO] - Starting API Key Server
[2025-04-23 14:32:15] [INFO] - Initializing database connection to apikeys.db
[2025-04-23 14:32:15] [INFO] - Database connection established successfully
[2025-04-23 14:32:15] [INFO] - Database schema initialized successfully
[2025-04-23 14:32:15] [INFO] - Starting HTTP server on 127.0.0.1:8081
[2025-04-23 14:32:15] [INFO] - Configuring application with routes and middleware
[2025-04-23 14:32:27] [INFO] - Received request to create API key for hex string: 0x123abc
[2025-04-23 14:32:27] [DEBUG] - Hex string validation passed for: 0x123abc
[2025-04-23 14:32:27] [DEBUG] - Generated new API key for hex string: 0x123abc
[2025-04-23 14:32:27] [DEBUG] - Successfully stored API key in database for: 0x123abc
[2025-04-23 14:32:27] [INFO] - Successfully created API key for hex string: 0x123abc
[2025-04-23 14:32:15] [INFO] - Configuring application with routes and middleware
[2025-04-23 14:32:27] [INFO] - Received request to create API key for hex string: 0x123abc
[2025-04-23 14:32:27] [DEBUG] - Hex string validation passed for: 0x123abc
[2025-04-23 14:32:27] [DEBUG] - Generated new API key for hex string: 0x123abc
[2025-04-23 14:32:27] [DEBUG] - Successfully stored API key in database for: 0x123abc
[2025-04-23 14:32:27] [INFO] - Successfully created API key for hex string: 0x123abc
```

## Implementation Details

- API keys are generated with a `sk_` prefix followed by URL-safe Base64 encoded random bytes
- SQLite database is used for persistent storage in a file named `apikeys.db`
- The server uses the Actix Web framework for handling HTTP requests
- Comprehensive error handling with descriptive error messages
- Thread-safe access to the database using Mutex
