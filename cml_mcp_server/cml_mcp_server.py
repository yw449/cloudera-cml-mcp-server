#!/usr/bin/env python3
"""
MCP server for interacting with Cloudera Machine Learning (CML)
"""

import os
import json
import requests
import urllib3
import argparse
import ssl
import socket
import certifi
import base64
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any, Union
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

def download_certificate(url: str, cert_file: str) -> bool:
    """Download SSL certificate from server and save it in PEM format
    
    Args:
        url: The server URL to download certificate from
        cert_file: Path where to save the certificate
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Parse the URL to get the hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443  # Default to 443 if port is not specified

        print(f"Downloading certificate from {hostname}:{port}...")

        # Create an SSL context using the system's trusted CA certificates
        context = ssl.create_default_context(cafile=certifi.where())
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Connect to the server and get the certificate
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_binary = ssock.getpeercert(binary_form=True)
                
                if not cert_binary:
                    print("Failed to get certificate")
                    return False

        # Convert binary certificate to plaintext PEM format
        b64_encoded = base64.b64encode(cert_binary).decode('ascii')
        
        # Add lines of 64 characters with proper PEM headers
        lines = ["-----BEGIN CERTIFICATE-----"]
        for i in range(0, len(b64_encoded), 64):
            lines.append(b64_encoded[i:i+64])
        lines.append("-----END CERTIFICATE-----")
        
        pem_cert = '\n'.join(lines)

        # Save the certificate to a file
        with open(cert_file, "w") as f:
            f.write(pem_cert)

        print(f"Certificate saved to {cert_file} in PEM format")
        return True
    except Exception as e:
        print(f"Error downloading certificate: {str(e)}")
        return False

def main():
    """Main entry point for the CML MCP server"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="MCP server for CML")
    parser.add_argument("--token", help="CML API token")
    parser.add_argument("--url", help="CML base URL")
    parser.add_argument("--cert", help="Path to SSL certificate file")
    parser.add_argument("--disable-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--download-cert", action="store_true", help="Force download of certificate")
    args = parser.parse_args()

    # Load environment variables from .env file
    load_dotenv()

    # Initialize FastMCP server
    mcp = FastMCP("cml")

    # CML API configuration - check environment variables with specific MCP naming convention first
    CML_API_TOKEN = args.token or os.getenv("CLOUDERA_ML_API_KEY") or os.getenv("CML_API_TOKEN")
    CML_BASE_URL = args.url or os.getenv("CLOUDERA_ML_HOST") or os.getenv("CML_BASE_URL")

    # Check if required environment variables are set
    if not CML_API_TOKEN:
        print("ERROR: CML API token not provided. Set CLOUDERA_ML_API_KEY or CML_API_TOKEN environment variable or use --token argument.")
        exit(1)

    if not CML_BASE_URL:
        print("ERROR: CML base URL not provided. Set CLOUDERA_ML_HOST or CML_BASE_URL environment variable or use --url argument.")
        exit(1)

    API_VERSION = "v2"
    CML_API_URL = f"{CML_BASE_URL}/api/{API_VERSION}"

    # Path to the certificate file - use static name cml_ca.pem
    default_cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cml_ca.pem")
    CERT_FILE = args.cert or os.getenv("CML_CERT_FILE", default_cert_path)

    # SSL verification setting
    DISABLE_SSL_VERIFY = args.disable_ssl_verify or os.getenv("DISABLE_SSL_VERIFY", "").lower() in ("true", "1", "yes")

    # Download certificate if requested or if the cert file doesn't exist
    if args.download_cert or (not DISABLE_SSL_VERIFY and not os.path.exists(CERT_FILE)):
        print(f"Certificate file does not exist or download requested. Attempting to download...")
        if download_certificate(CML_BASE_URL, CERT_FILE):
            print(f"Certificate downloaded successfully. Will use it for SSL verification.")
        else:
            print(f"WARNING: Failed to download certificate. SSL verification may fail.")

    # Default headers for API requests
    DEFAULT_HEADERS = {
        "Authorization": f"Bearer {CML_API_TOKEN}",
        "Content-Type": "application/json"
    }

    # Configure SSL verification
    def get_ssl_verification():
        """Determine the appropriate SSL verification setting"""
        if DISABLE_SSL_VERIFY:
            # Disable SSL verification warnings when explicitly disabled
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            print("WARNING: SSL verification is disabled. This is not recommended for production use.")
            return False
        
        # If a certificate file is specified
        if CERT_FILE:
            if os.path.exists(CERT_FILE):
                print(f"Using certificate file for SSL verification: {CERT_FILE}")
                return CERT_FILE
            else:
                print(f"WARNING: Certificate file not found: {CERT_FILE}")
                print("Falling back to default SSL verification.")
                return True
        
        # Default to using the system's CA bundle
        return True

    # Get the SSL verification setting
    SSL_VERIFY = get_ssl_verification()

    # Helper function for API requests
    def make_cml_request(method: str, endpoint: str, params: Dict = None, data: Dict = None, files: Dict = None) -> Dict:
        """Make a request to the CML API"""
        url = f"{CML_API_URL}/{endpoint}"
        
        try:
            headers = DEFAULT_HEADERS.copy()
            
            # If files are provided, we need to remove Content-Type header as it will be set automatically
            # with the correct multipart boundary
            if files:
                headers.pop("Content-Type", None)
                
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params, verify=SSL_VERIFY)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, params=params, json=data, files=files, verify=SSL_VERIFY)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=headers, params=params, json=data, files=files, verify=SSL_VERIFY)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, params=params, verify=SSL_VERIFY)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=headers, params=params, json=data, verify=SSL_VERIFY)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                error_msg = f"Error {e.response.status_code}: {e.response.text}"
            else:
                error_msg = str(e)
            raise Exception(f"API request failed: {error_msg}")

    # MCP Tool Implementations

    @mcp.tool()
    async def list_projects(search_filter: str = None, sort: str = None, 
                           page_size: int = None, page_token: str = None) -> str:
        """List all CML projects the user has access to.
        
        Args:
            search_filter: Optional JSON string to filter results (e.g. '{"name":"project-name"}')
            sort: Optional sort order (e.g. '+name' or '-created_at')
            page_size: Optional number of results per page
            page_token: Optional token for pagination
        """
        params = {
            "search_filter": search_filter,
            "sort": sort,
            "page_size": page_size,
            "page_token": page_token
        }
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        try:
            response = make_cml_request("GET", "projects", params=params)
            
            # Format the response for better readability
            projects_info = []
            for project in response.get("projects", []):
                projects_info.append({
                    "id": project.get("id", ""),
                    "name": project.get("name", ""),
                    "description": project.get("description", ""),
                    "owner": project.get("owner", {}).get("username", ""),
                    "created_at": project.get("created_at", "")
                })
            
            return json.dumps(projects_info, indent=2)
        except Exception as e:
            return f"Error listing projects: {str(e)}"

    @mcp.tool()
    async def create_project(name: str, description: str = "", visibility: str = "private", 
                           template: str = "local", environment: Dict = None) -> str:
        """Create a new CML project.
        
        Args:
            name: Name of the project
            description: Optional project description
            visibility: Project visibility (private, public, organization)
            template: Optional template to use (Python, R, PySpark, Scala, or local)
            environment: Optional environment variables as a dictionary
        """
        data = {
            "name": name,
            "description": description,
            "visibility": visibility,
            "template": template
        }
        
        if environment:
            data["environment"] = environment
        
        try:
            response = make_cml_request("POST", "projects", data=data)
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error creating project: {str(e)}"

    @mcp.tool()
    async def upload_file(project_id: str, file_path: str, content: str, overwrite: bool = False) -> str:
        """Upload a file to a CML project.
        
        Args:
            project_id: The ID of the project
            file_path: The path where the file should be created (relative to project root)
            content: The content of the file to upload
            overwrite: Whether to overwrite the file if it already exists
        """
        try:
            # Check if the file already exists
            if not overwrite:
                try:
                    # Try to get the file info - if it succeeds, the file exists
                    make_cml_request("GET", f"projects/{project_id}/files?path={file_path}")
                    return f"Error: File {file_path} already exists. Use overwrite=True to replace it."
                except Exception:
                    # If we get an exception, the file doesn't exist - proceed with upload
                    pass
            
            # Create a temporary file to upload
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp.write(content.encode('utf-8'))
                temp_path = temp.name
            
            # Upload the file
            with open(temp_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                
                # Extract the directory path
                dir_path = os.path.dirname(file_path)
                
                # Set up the parameters
                params = {}
                if dir_path:
                    params['path'] = dir_path
                
                response = make_cml_request(
                    "POST", 
                    f"projects/{project_id}/files", 
                    params=params,
                    files=files
                )
            
            # Clean up the temporary file
            os.unlink(temp_path)
            
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error uploading file: {str(e)}"

    @mcp.tool()
    async def rename_file(project_id: str, file_path: str, new_name: str) -> str:
        """Rename a file in a CML project.
        
        Args:
            project_id: The ID of the project
            file_path: The current path of the file (relative to project root)
            new_name: The new name for the file (without path)
        """
        try:
            # Get the directory path from the original file path
            dir_path = os.path.dirname(file_path)
            
            # Construct the new path by combining the directory path with the new name
            new_path = os.path.join(dir_path, new_name) if dir_path else new_name
            
            # Make the PATCH request to rename the file
            data = {
                "path": new_path
            }
            
            response = make_cml_request(
                "PATCH",
                f"projects/{project_id}/files?path={file_path}",
                data=data
            )
            
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error renaming file: {str(e)}"

    @mcp.tool()
    async def patch_file(project_id: str, file_path: str, new_path: str = None, new_name: str = None, 
                        metadata: Dict = None) -> str:
        """Update file metadata in a CML project, such as rename, move or change other attributes.
        
        Args:
            project_id: The ID of the project
            file_path: The current path of the file (relative to project root)
            new_path: Optional new full path for the file (directory + filename)
            new_name: Optional new name for the file (filename only)
            metadata: Optional additional metadata to update (as a dictionary)
        """
        try:
            # Initialize the data dictionary
            data = {}
            
            # Handle new_path parameter
            if new_path:
                data["path"] = new_path
            # Handle new_name parameter (only if new_path is not provided)
            elif new_name:
                # Get the directory path from the original file path
                dir_path = os.path.dirname(file_path)
                
                # Construct the new path by combining the directory path with the new name
                data["path"] = os.path.join(dir_path, new_name) if dir_path else new_name
            
            # Add any additional metadata
            if metadata:
                data.update(metadata)
            
            # Only proceed if we have data to update
            if data:
                response = make_cml_request(
                    "PATCH",
                    f"projects/{project_id}/files?path={file_path}",
                    data=data
                )
                
                return json.dumps(response, indent=2)
            else:
                return "Error: No update parameters provided. Specify at least one of: new_path, new_name, or metadata."
        except Exception as e:
            return f"Error updating file: {str(e)}"

    @mcp.tool()
    async def create_job_from_file(project_id: str, name: str, script: str, 
                                 kernel: str = "python3", cpu: float = None, 
                                 memory: float = None, runtime_identifier: str = None, runtime_addon_identifiers: list = None) -> str:
        """Create a job from a file in a CML project.
        
        Args:
            project_id: The ID of the project
            name: Name of the job
            script: Script file name (relative to project root)
            kernel: Kernel to use (default: python3)
            cpu: CPU cores to allocate (optional)
            memory: Memory in GB to allocate (optional)
            runtime_identifier: Runtime identifier to use (for ML Runtime projects)
            runtime_addon_identifiers: List of runtime addon identifiers (for ML Runtime projects)
        """
        try:
            data = {
                "name": name,
                "script": script,
                "kernel": kernel
            }
            
            # Add optional parameters if provided
            if cpu is not None:
                data["cpu"] = cpu
            if memory is not None:
                data["memory"] = memory
            if runtime_identifier is not None:
                data["runtime_identifier"] = runtime_identifier
            if runtime_addon_identifiers is not None:
                data["runtime_addon_identifiers"] = runtime_addon_identifiers
            
            response = make_cml_request("POST", f"projects/{project_id}/jobs", data=data)
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error creating job: {str(e)}"

    @mcp.tool()
    async def get_project(project_id: str) -> str:
        """Get details of a specific CML project.
        
        Args:
            project_id: The ID of the project
        """
        try:
            response = make_cml_request("GET", f"projects/{project_id}")
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error getting project details: {str(e)}"

    @mcp.tool()
    async def list_files(project_id: str, path: str = "") -> str:
        """List files in a CML project at the specified path.
        
        Args:
            project_id: The ID of the project
            path: The path to list files from (relative to project root)
        """
        try:
            params = {}
            if path:
                params["path"] = path
                
            response = make_cml_request("GET", f"projects/{project_id}/files", params=params)
            
            # Format the response for better readability
            files_info = []
            for file_info in response.get("files", []):
                files_info.append({
                    "name": file_info.get("name", ""),
                    "path": file_info.get("path", ""),
                    "type": file_info.get("type", ""),
                    "size": file_info.get("size", 0)
                })
            
            return json.dumps(files_info, indent=2)
        except Exception as e:
            return f"Error listing files: {str(e)}"

    @mcp.tool()
    async def read_file(project_id: str, file_path: str) -> str:
        """Read the contents of a file from a CML project.
        
        Args:
            project_id: The ID of the project
            file_path: The path to the file (relative to project root)
        """
        try:
            response = make_cml_request("GET", f"projects/{project_id}/files/content?path={file_path}")
            
            # The content is usually in the 'content' field
            if "content" in response:
                return response["content"]
            else:
                return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error reading file: {str(e)}"

    @mcp.tool()
    async def list_jobs(project_id: str, search_filter: str = None, 
                       sort: str = None, page_size: int = None, page_token: str = None) -> str:
        """List all jobs in a CML project.
        
        Args:
            project_id: The ID of the project
            search_filter: Optional JSON string to filter results (e.g. '{"name":"job-name"}')
            sort: Optional sort order (e.g. '+name' or '-created_at')
            page_size: Optional number of results per page
            page_token: Optional token for pagination
        """
        params = {
            "search_filter": search_filter,
            "sort": sort,
            "page_size": page_size,
            "page_token": page_token
        }
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        try:
            response = make_cml_request("GET", f"projects/{project_id}/jobs", params=params)
            
            # Format the response for better readability
            jobs_info = []
            for job in response.get("jobs", []):
                jobs_info.append({
                    "id": job.get("id", ""),
                    "name": job.get("name", ""),
                    "script": job.get("script", ""),
                    "kernel": job.get("kernel", ""),
                    "cpu": job.get("cpu", 0),
                    "memory": job.get("memory", 0),
                    "runtime": job.get("runtime", {}),
                    "runtime_identifier": job.get("runtime_identifier", ""),
                    "runtime_addon_identifiers": job.get("runtime_addon_identifiers", []),
                    "created_at": job.get("created_at", ""),
                    "updated_at": job.get("updated_at", "")
                })
            
            return json.dumps(jobs_info, indent=2)
        except Exception as e:
            return f"Error listing jobs: {str(e)}"

    @mcp.tool()
    async def create_job(project_id: str, name: str, script: str, 
                        kernel: str = "python3", cpu: float = None, 
                        memory: float = None, runtime_identifier: str = None, runtime_addon_identifiers: list = None) -> str:
        """Create a new job in a CML project.
        
        Args:
            project_id: The ID of the project
            name: Name of the job
            script: Path to the script to run
            kernel: Kernel to use (default: python3)
            cpu: CPU cores to allocate (optional)
            memory: Memory in GB to allocate (optional)
            runtime_identifier: Runtime identifier to use (for ML Runtime projects)
            runtime_addon_identifiers: List of runtime addon identifiers (for ML Runtime projects)
        """
        try:
            data = {
                "name": name,
                "script": script,
                "kernel": kernel
            }
            
            # Add optional parameters if provided
            if cpu is not None:
                data["cpu"] = cpu
            if memory is not None:
                data["memory"] = memory
            if runtime_identifier is not None:
                data["runtime_identifier"] = runtime_identifier
            if runtime_addon_identifiers is not None:
                data["runtime_addon_identifiers"] = runtime_addon_identifiers
            
            response = make_cml_request("POST", f"projects/{project_id}/jobs", data=data)
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error creating job: {str(e)}"

    @mcp.tool()
    async def run_job(project_id: str, job_id: str) -> str:
        """Run a job in a CML project.
        
        Args:
            project_id: The ID of the project
            job_id: The ID of the job to run
        """
        try:
            response = make_cml_request("POST", f"projects/{project_id}/jobs/{job_id}/runs")
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error running job: {str(e)}"

    @mcp.tool()
    async def list_job_runs(project_id: str, job_id: str, search_filter: str = None,
                           sort: str = None, page_size: int = None, page_token: str = None) -> str:
        """List all runs for a job in a CML project.
        
        Args:
            project_id: The ID of the project
            job_id: The ID of the job
            search_filter: Optional JSON string to filter results (e.g. '{"status":"running"}')
            sort: Optional sort order (e.g. '+created_at' or '-finished_at')
            page_size: Optional number of results per page
            page_token: Optional token for pagination
        """
        params = {
            "search_filter": search_filter,
            "sort": sort,
            "page_size": page_size,
            "page_token": page_token
        }
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        try:
            response = make_cml_request("GET", f"projects/{project_id}/jobs/{job_id}/runs", params=params)
            
            # Format the response for better readability
            runs_info = []
            for run in response.get("runs", []):
                runs_info.append({
                    "id": run.get("id", ""),
                    "status": run.get("status", ""),
                    "created_at": run.get("created_at", ""),
                    "started_at": run.get("started_at", ""),
                    "finished_at": run.get("finished_at", ""),
                    "engine_id": run.get("engine_id", "")
                })
            
            return json.dumps(runs_info, indent=2)
        except Exception as e:
            return f"Error listing job runs: {str(e)}"

    @mcp.tool()
    async def stop_job_run(project_id: str, job_id: str, run_id: str) -> str:
        """Stop a running job in a CML project.
        
        Args:
            project_id: The ID of the project
            job_id: The ID of the job
            run_id: The ID of the job run to stop
        """
        try:
            response = make_cml_request("POST", f"projects/{project_id}/jobs/{job_id}/runs/{run_id}/stop")
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error stopping job run: {str(e)}"

    @mcp.tool()
    async def schedule_job(project_id: str, job_id: str, cron_expression: str) -> str:
        """Schedule a job to run periodically using a cron expression.
        
        Args:
            project_id: The ID of the project
            job_id: The ID of the job
            cron_expression: Cron expression for scheduling (e.g. "0 0 * * *" for daily at midnight)
        """
        try:
            data = {
                "cron": cron_expression
            }
            response = make_cml_request("POST", f"projects/{project_id}/jobs/{job_id}/schedule", data=data)
            return json.dumps(response, indent=2)
        except Exception as e:
            return f"Error scheduling job: {str(e)}"

    @mcp.tool()
    async def list_runtime_addons(search_filter: str = None, sort: str = None, 
                                page_size: int = None, page_token: str = None) -> str:
        """List all available runtime addons (e.g., Spark3, GPU, etc.).
        """
        params = {
            "search_filter": search_filter,
            "sort": sort,
            "page_size": page_size,
            "page_token": page_token
        }
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        try:
            response = make_cml_request("GET", "runtimes/addons", params=params)
            
            # Format the response for better readability
            addons_info = []
            
            # Check if the response has runtime_addons key
            if "runtime_addons" in response:
                for addon in response.get("runtime_addons", []):
                    addons_info.append({
                        "id": addon.get("id", ""),
                        "name": addon.get("name", ""),
                        "description": addon.get("description", ""),
                        "image_identifier": addon.get("image_identifier", ""),
                        "kernel_name": addon.get("kernel_name", "")
                    })
            else:
                # Fallback to direct response processing if structure is different
                for addon in response:
                    if isinstance(addon, dict):
                        addons_info.append({
                            "id": addon.get("id", ""),
                            "name": addon.get("name", ""),
                            "description": addon.get("description", ""),
                            "image_identifier": addon.get("image_identifier", ""),
                            "kernel_name": addon.get("kernel_name", "")
                        })
            
            return json.dumps(addons_info, indent=2)
        except Exception as e:
            return f"Error listing runtime addons: {str(e)}"

    @mcp.tool()
    async def download_ssl_cert() -> str:
        """Download the SSL certificate from the CML server.
        
        This tool will download the SSL certificate from the CML server
        and save it for future use. This is useful if you're experiencing
        SSL verification issues.
        """
        try:
            if not CML_BASE_URL:
                return "Error: CML base URL not set. Please set CLOUDERA_ML_HOST or CML_BASE_URL environment variable."
                
            cert_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cml_ca.pem")
            
            if download_certificate(CML_BASE_URL, cert_file):
                return f"Certificate successfully downloaded and saved to {cert_file}"
            else:
                return "Failed to download certificate. Check the server URL and connectivity."
        except Exception as e:
            return f"Error downloading certificate: {str(e)}"

    # Start the server
    mcp.run()

if __name__ == "__main__":
    main()