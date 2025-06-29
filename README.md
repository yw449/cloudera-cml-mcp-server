# CML MCP Server

A standalone MCP (Model Context Protocol) server for interacting with Cloudera Machine Learning (CML).

## Requirements

- Python 3.8+
- Required Python packages:
  - mcp[cli]>=1.2.0
  - requests>=2.31.0

## Installation

1. Install the required packages:

```bash
pip install mcp[cli] requests
```

Or with uv:

```bash
uv pip install mcp[cli] requests
```

2. Set up environment variables (optional):

```bash
# Traditional environment variables
export CML_API_TOKEN="your_api_token_here"
export CML_BASE_URL="https://your-cml-instance.cloudera.com"

# MCP configuration environment variables (preferred)
export CLOUDERA_ML_API_KEY="your_api_token_here"
export CLOUDERA_ML_HOST="https://your-cml-instance.cloudera.com"

# Certificate path (optional)
export CML_CERT_FILE="/path/to/your/certificate.pem"
```

3. Download the SSL certificate from your CML server (if using a self-signed certificate):

```bash
python download_certificate.py
```

This will download the certificate from the CML server specified in the CLOUDERA_ML_HOST or CML_BASE_URL environment variable and save it to `cml_ca.pem`.

## Usage

You can run the server using any of these commands:

```bash
# Using standard Python
python3 cml_mcp_server.py

# Using uv
uv run cml_mcp_server.py

# Using uvx
uvx cml_mcp_server.py
```

For help and configuration information:

```bash
python3 cml_mcp_server.py --help
```

You can also specify custom parameters:

```bash
python3 cml_mcp_server.py --token "your_api_token" --url "https://your-cml-instance.cloudera.com" --cert "/path/to/your/certificate.pem"
```

## Direct Usage

You can also use the direct script to list projects without using the MCP server:

```bash
python direct_list_projects.py
```

## Integration with Claude for Desktop

To use this server with Claude for Desktop:

1. Create a `claude_desktop_config.json` file in your Claude for Desktop configuration directory
2. Add the following configuration (update the path to match your server location):

```json
{
  "mcpServers": {
    "cml": {
      "command": "uv",
      "args": ["run", "/full/path/to/cml_mcp_server.py"],
      "env": {
        "CLOUDERA_ML_HOST": "https://your-cml-instance.cloudera.com",
        "CLOUDERA_ML_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Alternatively, you can use the `uv` Python package manager to run the server (recommended):

```json
{
  "mcpServers": {
    "cml": {
      "command": "python3",
      "args": ["/full/path/to/cml_mcp_server.py"],
      "env": {
        "CLOUDERA_ML_HOST": "https://your-cml-instance.cloudera.com",
        "CLOUDERA_ML_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

The `uv` method provides better dependency isolation and faster startup times compared to standard Python execution.

## Available Tools

The server provides the following MCP tools for interacting with CML:

### Project Management
- `list_projects`: List all CML projects the user has access to
- `create_project`: Create a new CML project
- `get_project`: Get details of a specific CML project

### File Operations
- `list_files`: List files in a CML project at the specified path
- `read_file`: Read the contents of a file from a CML project
- `upload_file`: Upload a file to a CML project
- `rename_file`: Rename a file in a CML project
- `patch_file`: Update file metadata (rename, move, or change attributes)

### Job Management
- `list_jobs`: List all jobs in a CML project
- `create_job`: Create a new job in a CML project
- `create_job_from_file`: Create a job from an existing file in a CML project
- `run_job`: Run a job in a CML project
- `list_job_runs`: List all runs for a job in a CML project
- `stop_job_run`: Stop a running job in a CML project
- `schedule_job`: Schedule a job to run periodically using a cron expression

### Runtime Management
- `list_runtime_addons`: List all available runtime addons (e.g., Spark3, GPU)
- `download_ssl_cert`: Download the SSL certificate from the CML server