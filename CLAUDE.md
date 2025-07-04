# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

YaraXServer is a Rust-based web server that provides a RESTful API for managing YARA rules and files. It's built with Actix Web and uses PostgreSQL via SeaORM for data persistence. The server handles YARA rule compilation, scanning, and provides comprehensive CRUD operations for rule management.

## Key Architecture

- **Main Server**: `src/main.rs` - Actix Web server with REST API endpoints
- **Database Models**: `src/entity/` - SeaORM entities for PostgreSQL integration
- **Data Models**: `src/models.rs` - API request/response structures
- **YARA Integration**: `src/yara.rs` - YARA rule compilation and scanning logic
- **Tokenizer**: `src/tokenizer.rs` - YARA file parsing and manipulation
- **Database Schema**: `yaraxserver.sql` - PostgreSQL schema definition

## Development Commands

### Build and Run
```bash
# Build the project
cargo build

# Run in development mode
cargo run

# Run with specific host/port
cargo run -- --host 0.0.0.0 --port 7779
```

### Database Operations
- Database configuration is handled via `DATABASE_URL` environment variable
- SeaORM configuration is in `sea-orm-cli.toml`
- Database schema is defined in `yaraxserver.sql`

### Testing
```bash
# Run Rust tests
cargo test

# Run Python API tests (requires server running on localhost:8080)
python -m unittest tests/test_api_*.py
```

### Docker Deployment
```bash
# Build Docker image
docker build -t yaraxserver:latest .

# Run with Docker Compose
docker-compose up
```

## API Structure

The server provides REST endpoints for:
- **YARA File Management**: `/api/yara_file/*` - CRUD operations for YARA file collections
- **Rule Management**: `/api/rule/*` - Individual YARA rule operations
- **Compilation**: `/api/create`, `/api/add` - Create and compile YARA rules
- **Scanning**: `/api/scan` - Scan files against compiled rules
- **Utilities**: `/api/reload`, `/api/update`, `/api/delete` - Management operations

## Database Schema

The application uses three main entities:
- `yara_file` - Collections of YARA rules
- `yara_rules` - Individual YARA rules with metadata
- `yara_rule_history` - Historical versions of rules

## Key Dependencies

- **yara-x**: YARA rule compilation and matching
- **actix-web**: Web framework
- **sea-orm**: ORM for PostgreSQL
- **serde**: JSON serialization/deserialization
- **pest**: YARA file parsing
- **base64**: Binary data encoding for API responses

## Development Notes

- The server uses `mimalloc` for memory allocation optimization
- Logging is handled via `env_logger` and `log` crate
- YARA files are parsed using a custom pest grammar (`src/yara.pest`)
- Binary data (compiled YARA rules) is base64-encoded in API responses
- The server supports file upload via multipart forms for YARA file scanning

## Testing Strategy

- Unit tests are in the `tests/` directory as Python files
- Tests require the server to be running on `localhost:8080`
- Tests cover all major API endpoints including create, update, delete, scan operations
- Test data includes sample YARA rules and binary files for scanning