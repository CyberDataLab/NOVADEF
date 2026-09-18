"""
configuration_manager_api.py  (v3)

FastAPI application for the Configuration Manager.
This file only handles HTTP routing and request/response formatting.
All business logic is delegated to configuration_manager_logic.py.

Changes from v2:
- toolName is now a query parameter in all deploy endpoints, not inside the JSON body.
- Each deploy endpoint accepts exactly one tool per request.
- The JSON body only contains the optional 'configuration' dict with env var overrides.

Launch with:
    uvicorn configuration_manager_api:app --host 0.0.0.0 --port 8000
Or with whole path:
    uvicorn --app-dir APIs/ConfigurationManager configuration_manager_api:app --port 8000 --host 0.0.0.0
Or directly with Python:
    python3 configuration_manager_api.py --port 9000 --reload

Example request:
    POST /ConfigurationManager/DeployNetworkTool?toolName=tshark
    Body: {"configuration": {"TSHARK_BASE_TOPIC": "my_topic"}}

    POST /ConfigurationManager/DeployNetworkTool?toolName=tshark
    Body: {}
"""

from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from configuration_manager_logic import (
    DeployRequest,
    DeploySecurityRequest,
    UpdateConfigurationRequest,
    get_configuration_options,
    get_configuration_by_id,
    get_kafka_topics_state,
    get_tool_runtime_state,
)
from job_manager import check_jobs_backend_ready, get_job_manager

app = FastAPI(
    title="Configuration Manager API",
    description=(
        "API for deploying and configuring PMP monitoring tools. "
        "Supports network, infrastructure, service and security tool deployment. "
        "toolName is passed as a query parameter; the JSON body carries only env var overrides."
    ),
    version="3.1.0",
)

# ---------------------------------------------------------------------------
# Valid tool names per endpoint
# ---------------------------------------------------------------------------
NETWORK_TOOLS        = ["tshark", "flow_module"]
INFRASTRUCTURE_TOOLS = ["telegraf"]
SERVICE_TOOLS        = ["fluentd", "falco"]
SECURITY_TOOLS       = ["snort3"]


@app.get("/")
async def root():
    """
    Health check endpoint. Returns API status and version.
    """
    return {
        "message":          "Configuration Manager API is running",
        "version":          "3.1.0",
        "kafka_bootstrap":  "kafka_novadef-node1.lan:9094",
    }


@app.post("/ConfigurationManager/DeployNetworkTool")
async def deploy_network_tool(
    toolName: str = Query(..., description="Name of the network tool to deploy. Valid values: tshark, flow_module"),
    request: DeployRequest = None
):
    """
    Deploy a network monitoring tool (tshark or flow_module).

    - toolName: query parameter with the tool to deploy.
    - Body: optional JSON with env var overrides. Send {} or omit body to use all defaults.

    Examples:
        POST /ConfigurationManager/DeployNetworkTool?toolName=tshark
        Body: {}

        POST /ConfigurationManager/DeployNetworkTool?toolName=tshark
        Body: {"configuration": {"TSHARK_BASE_TOPIC": "my_topic"}}
    """
    if request is None:
        request = DeployRequest()

    if toolName not in NETWORK_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Tool '{toolName}' is not valid for endpoint 'DeployNetworkTool'. "
                f"Allowed tools: {NETWORK_TOOLS}"
            ),
        )

    is_ready, readiness_error = check_jobs_backend_ready()
    if not is_ready:
        raise HTTPException(status_code=503, detail=readiness_error)

    job_manager = get_job_manager()
    result = job_manager.enqueue_deploy_job(
        endpoint="DeployNetworkTool",
        tool_name=toolName,
        request_payload=request.model_dump(),
        allowed_tool_names=NETWORK_TOOLS,
    )
    return JSONResponse(status_code=202, content=result)


@app.post("/ConfigurationManager/DeployInfrastructureTool")
async def deploy_infrastructure_tool(
    toolName: str = Query(..., description="Name of the infrastructure tool to deploy. Valid values: telegraf"),
    request: DeployRequest = None
):
    """
    Deploy an infrastructure monitoring tool (telegraf).

    - toolName: query parameter with the tool to deploy.
    - Body: optional JSON with env var overrides. Send {} or omit body to use all defaults.

    Example:
        POST /ConfigurationManager/DeployInfrastructureTool?toolName=telegraf
        Body: {"configuration": {"TELEGRAF_GENERAL_INTERVAL": "60s"}}
    """
    if request is None:
        request = DeployRequest()

    if toolName not in INFRASTRUCTURE_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Tool '{toolName}' is not valid for endpoint 'DeployInfrastructureTool'. "
                f"Allowed tools: {INFRASTRUCTURE_TOOLS}"
            ),
        )

    is_ready, readiness_error = check_jobs_backend_ready()
    if not is_ready:
        raise HTTPException(status_code=503, detail=readiness_error)

    job_manager = get_job_manager()
    result = job_manager.enqueue_deploy_job(
        endpoint="DeployInfrastructureTool",
        tool_name=toolName,
        request_payload=request.model_dump(),
        allowed_tool_names=INFRASTRUCTURE_TOOLS,
    )
    return JSONResponse(status_code=202, content=result)


@app.post("/ConfigurationManager/DeployServiceTool")
async def deploy_service_tool(
    toolName: str = Query(..., description="Name of the service tool to deploy. Valid values: fluentd, falco"),
    request: DeployRequest = None
):
    """
    Deploy a service monitoring tool (fluentd or falco).

    - toolName: query parameter with the tool to deploy.
    - Body: optional JSON with env var overrides. Send {} or omit body to use all defaults.

    Example:
        POST /ConfigurationManager/DeployServiceTool?toolName=falco
        Body: {"configuration": {"FALCO_EXPORTER_PORT": "9377"}}
    """
    if request is None:
        request = DeployRequest()

    if toolName not in SERVICE_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Tool '{toolName}' is not valid for endpoint 'DeployServiceTool'. "
                f"Allowed tools: {SERVICE_TOOLS}"
            ),
        )

    is_ready, readiness_error = check_jobs_backend_ready()
    if not is_ready:
        raise HTTPException(status_code=503, detail=readiness_error)

    job_manager = get_job_manager()
    result = job_manager.enqueue_deploy_job(
        endpoint="DeployServiceTool",
        tool_name=toolName,
        request_payload=request.model_dump(),
        allowed_tool_names=SERVICE_TOOLS,
    )
    return JSONResponse(status_code=202, content=result)


@app.post("/ConfigurationManager/DeploySecurityTool")
async def deploy_security_tool(
    toolName: str = Query(..., description="Name of the security tool to deploy. Valid values: snort3"),
    request: DeploySecurityRequest = None
):
    """
    Deploy a security tool (snort3).

    - toolName: query parameter with the tool to deploy.
    - Body: optional JSON with env var overrides and optional custom rules payload.

    Example:
        POST /ConfigurationManager/DeploySecurityTool?toolName=snort3
        Body: {"configuration": {"SNORT_KAFKA_TOPIC_OUT": "my_alerts"}}
    """
    if request is None:
        request = DeploySecurityRequest()

    if toolName not in SECURITY_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Tool '{toolName}' is not valid for endpoint 'DeploySecurityTool'. "
                f"Allowed tools: {SECURITY_TOOLS}"
            ),
        )

    is_ready, readiness_error = check_jobs_backend_ready()
    if not is_ready:
        raise HTTPException(status_code=503, detail=readiness_error)

    job_manager = get_job_manager()
    result = job_manager.enqueue_deploy_job(
        endpoint="DeploySecurityTool",
        tool_name=toolName,
        request_payload=request.model_dump(),
        allowed_tool_names=SECURITY_TOOLS,
    )
    return JSONResponse(status_code=202, content=result)


@app.get("/ConfigurationManager/getConfigurationOptions")
async def get_configuration_options_endpoint(
    toolName: str = Query(..., description="Name of the tool to query options for.")
):
    """
    Return all configurable environment variables for a given tool with their default values.
    Defaults are read directly from the Pydantic model for that tool.

    Example: GET /ConfigurationManager/getConfigurationOptions?toolName=tshark
    """
    result = get_configuration_options(toolName)

    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["message"])

    return JSONResponse(status_code=200, content=result)


@app.get("/ConfigurationManager/getConfiguration")
async def get_configuration_endpoint(
    config_id: str = Query(..., description="The config_id hash returned by a previous deploy call.")
):
    """
    Retrieve a stored deployment configuration from MongoDB by its config_id.

    Example: GET /ConfigurationManager/getConfiguration?config_id=<hash>
    """
    result = get_configuration_by_id(config_id)

    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["message"])

    return JSONResponse(status_code=200, content=result)


@app.get("/ConfigurationManager/getKafkaTopicsState")
async def get_kafka_topics_state_endpoint():
    """
    Return the current kafka_topics document persisted by producer deployments.

    This is useful for clients that need to know whether upstream producers such
    as tshark have already published their resolved topic configuration.
    """
    result = get_kafka_topics_state()

    if result.get("status") == "error":
        raise HTTPException(status_code=503, detail=result["message"])

    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=result["message"])

    return JSONResponse(status_code=200, content=result)


@app.get("/ConfigurationManager/getToolRuntimeState")
async def get_tool_runtime_state_endpoint(
    toolName: str = Query(..., description="Name of the tool whose runtime state should be checked.")
):
    """
    Return the runtime state of the main Docker container associated with a tool.
    """
    result = get_tool_runtime_state(toolName)

    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["message"])

    return JSONResponse(status_code=200, content=result)


@app.put("/ConfigurationManager/updateConfiguration")
async def update_configuration_endpoint(
    toolName: str = Query(..., description="Name of the tool to update."),
    request: UpdateConfigurationRequest = None
):
    """
    Update an existing deployment configuration identified by config_id.
    Retrieves the stored configuration, merges the new values, and redeploys.
    Only the variables explicitly sent are overridden; the rest keep their stored values.

    - toolName: query parameter indicating which tool's config model to use for validation.
    - Body: JSON with config_id, optional configuration overrides and optional managed-rules contract.

    Example:
        PUT /ConfigurationManager/updateConfiguration?toolName=tshark
        Body: {"config_id": "<hash>", "configuration": {"TSHARK_BASE_TOPIC": "new_topic"}}
    """
    if request is None:
        raise HTTPException(status_code=422, detail="Request body with config_id is required.")

    if not isSupportedToolName(toolName):
        raise HTTPException(status_code=400, detail=f"Unknown toolName '{toolName}'.")

    is_ready, readiness_error = check_jobs_backend_ready()
    if not is_ready:
        raise HTTPException(status_code=503, detail=readiness_error)

    job_manager = get_job_manager()
    result = job_manager.enqueue_update_job(
        tool_name=toolName,
        request_payload=request.model_dump(),
    )
    return JSONResponse(status_code=202, content=result)


@app.get("/ConfigurationManager/internal/jobs/{job_id}")
async def get_internal_job_status(job_id: str):
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' was not found.")
    return JSONResponse(status_code=200, content=jsonable_encoder(job))


@app.get("/ConfigurationManager/internal/jobs")
async def list_internal_jobs(
    status: Optional[str] = Query(default=None, description="Optional status filter."),
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of jobs to return."),
):
    job_manager = get_job_manager()
    jobs = job_manager.list_jobs(status=status, limit=limit)
    return JSONResponse(status_code=200, content=jsonable_encoder({"status": "success", "data": jobs}))


@app.post("/ConfigurationManager/internal/jobs/{job_id}/cancel")
async def cancel_internal_job(job_id: str):
    job_manager = get_job_manager()
    canceled, error_message = job_manager.cancel_job(job_id)
    if not canceled:
        raise HTTPException(status_code=400, detail=error_message)
    return JSONResponse(status_code=200, content={"status": "success", "message": f"Job '{job_id}' canceled."})


@app.on_event("startup")
async def startup_job_manager():
    get_job_manager().start()


def isSupportedToolName(tool_name: str) -> bool:
    return (
        tool_name in NETWORK_TOOLS
        or tool_name in INFRASTRUCTURE_TOOLS
        or tool_name in SERVICE_TOOLS
        or tool_name in SECURITY_TOOLS
    )


if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Configuration Manager API server")
    parser.add_argument("--host",   default="0.0.0.0",      help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=8000,  help="Port to listen on (default: 8000)")
    parser.add_argument("--reload", action="store_true",     help="Enable auto-reload on file changes")
    args = parser.parse_args()

    uvicorn.run(
        "configuration_manager_api:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )
