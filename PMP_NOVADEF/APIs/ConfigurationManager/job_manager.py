from __future__ import annotations

import socket
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from pymongo import ASCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from configuration_manager_logic import (
    DeployRequest,
    DeploySecurityRequest,
    MONGO_CM_DB,
    MONGO_CM_URI,
    UpdateConfigurationRequest,
    process_deploy_request,
    process_update_configuration,
)

JOBS_COLLECTION_NAME = "deploy_jobs"
JOB_TTL_DAYS = 15
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = [5, 15]

RETRYABLE_MARKERS = (
    "Error during launch:",
    "timed out",
    "timeout",
    "docker",
    "compose",
    "temporary",
    "connection reset",
    "connection refused",
)

NON_RETRYABLE_MARKERS = (
    "Invalid configuration",
    "Unknown toolName",
    "Tool '",
    "must be",
    "requires",
    "rules_action",
    "validation failed",
    "Cannot set include_default_rules",
    "No configuration values were provided",
    "Missing config_id",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def build_api_instance_id() -> str:
    return f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"


class ConfigurationManagerJobQueue:
    def __init__(self) -> None:
        self.api_instance_id = build_api_instance_id()
        self.worker_id = "cm-worker-1"
        self._mongo_client = MongoClient(MONGO_CM_URI, serverSelectionTimeoutMS=3000)
        self._collection: Collection = self._mongo_client[MONGO_CM_DB][JOBS_COLLECTION_NAME]
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._queued_job_ids: Deque[str] = deque()
        self._running_job_id: Optional[str] = None
        self._started = False
        self._stop_requested = False
        self._worker_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stop_requested = False

        self._ensure_indexes()
        self._recover_jobs()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="configuration-manager-job-worker",
            daemon=True,
        )
        self._worker_thread.start()

    def stop(self) -> None:
        with self._condition:
            self._stop_requested = True
            self._condition.notify_all()

    def enqueue_deploy_job(
        self,
        *,
        endpoint: str,
        tool_name: str,
        request_payload: Dict[str, Any],
        allowed_tool_names: List[str],
    ) -> Dict[str, Any]:
        return self._enqueue_job(
            job_type="deploy",
            endpoint=endpoint,
            tool_name=tool_name,
            request_payload=request_payload,
            allowed_tool_names=allowed_tool_names,
        )

    def enqueue_update_job(
        self,
        *,
        tool_name: str,
        request_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        return self._enqueue_job(
            job_type="update",
            endpoint="updateConfiguration",
            tool_name=tool_name,
            request_payload=request_payload,
            allowed_tool_names=[],
        )

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self._collection.find_one({"_id": job_id})
        except PyMongoError:
            return None

    def list_jobs(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if status:
            query["status"] = status
        safe_limit = max(1, min(limit, 200))
        return list(
            self._collection.find(query).sort("created_at", ASCENDING).limit(safe_limit)
        )

    def cancel_job(self, job_id: str) -> Tuple[bool, str]:
        with self._lock:
            job = self.get_job(job_id)
            if job is None:
                return False, "Job not found."
            if job.get("status") != "queued":
                return False, "Only queued jobs can be canceled."

            self._queued_job_ids = deque(
                existing_job_id
                for existing_job_id in self._queued_job_ids
                if existing_job_id != job_id
            )

        self._collection.update_one(
            {"_id": job_id},
            {
                "$set": {
                    "status": "canceled",
                    "stage": "done",
                    "finished_at": utc_now(),
                    "updated_at": utc_now(),
                }
            },
        )
        return True, ""

    def _enqueue_job(
        self,
        *,
        job_type: str,
        endpoint: str,
        tool_name: str,
        request_payload: Dict[str, Any],
        allowed_tool_names: List[str],
    ) -> Dict[str, Any]:
        job_id = uuid.uuid4().hex
        now = utc_now()
        document = {
            "_id": job_id,
            "job_type": job_type,
            "endpoint": endpoint,
            "tool_name": tool_name,
            "request_payload": request_payload,
            "allowed_tool_names": allowed_tool_names,
            "status": "queued",
            "stage": "queued",
            "attempt": 1,
            "max_attempts": MAX_ATTEMPTS,
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "finished_at": None,
            "worker_id": self.worker_id,
            "api_instance_id": self.api_instance_id,
            "result": None,
            "error": None,
            "retry": {"is_retryable": False, "next_retry_at": None},
            "ttl_expire_at": now + timedelta(days=JOB_TTL_DAYS),
        }
        self._collection.insert_one(document)

        with self._condition:
            self._queued_job_ids.append(job_id)
            queue_position = len(self._queued_job_ids) + (1 if self._running_job_id else 0)
            self._condition.notify()

        return {
            "status": "accepted",
            "message": "Deployment job queued.",
            "job_id": job_id,
            "job_status": "queued",
            "queue_position": queue_position,
        }

    def _ensure_indexes(self) -> None:
        self._collection.create_index([("status", ASCENDING), ("created_at", ASCENDING)])
        self._collection.create_index(
            [("ttl_expire_at", ASCENDING)],
            expireAfterSeconds=0,
        )

    def _recover_jobs(self) -> None:
        now = utc_now()
        self._collection.update_many(
            {"status": "running"},
            {
                "$set": {
                    "status": "failed",
                    "stage": "done",
                    "updated_at": now,
                    "finished_at": now,
                    "error": {
                        "code": "WORKER_RESTARTED",
                        "user_message": "The job was interrupted because the API worker restarted.",
                        "technical_message": "Running job marked as failed during recovery.",
                    },
                }
            },
        )

        queued_jobs = self._collection.find({"status": "queued"}).sort("created_at", ASCENDING)
        with self._lock:
            self._queued_job_ids.clear()
            for job in queued_jobs:
                self._queued_job_ids.append(str(job["_id"]))

    def _worker_loop(self) -> None:
        while True:
            with self._condition:
                while not self._queued_job_ids and not self._stop_requested:
                    self._condition.wait()
                if self._stop_requested:
                    return
                job_id = self._queued_job_ids.popleft()
                self._running_job_id = job_id

            try:
                self._execute_job(job_id)
            finally:
                with self._condition:
                    self._running_job_id = None
                    self._condition.notify_all()

    def _execute_job(self, job_id: str) -> None:
        job = self.get_job(job_id)
        if job is None:
            return

        attempt = 1
        max_attempts = int(job.get("max_attempts") or MAX_ATTEMPTS)

        while attempt <= max_attempts:
            now = utc_now()
            self._collection.update_one(
                {"_id": job_id},
                {
                    "$set": {
                        "status": "running",
                        "stage": "validating_request",
                        "attempt": attempt,
                        "updated_at": now,
                        "started_at": now if attempt == 1 else job.get("started_at") or now,
                        "error": None,
                    }
                },
            )

            ok, result, error = self._execute_job_once(job_id)
            if ok:
                finished_at = utc_now()
                self._collection.update_one(
                    {"_id": job_id},
                    {
                        "$set": {
                            "status": "succeeded",
                            "stage": "done",
                            "result": result,
                            "updated_at": finished_at,
                            "finished_at": finished_at,
                            "ttl_expire_at": finished_at + timedelta(days=JOB_TTL_DAYS),
                        }
                    },
                )
                return

            retryable = self._is_retryable_error(str(error.get("technical_message", "")))
            if retryable and attempt < max_attempts:
                retry_delay = RETRY_BACKOFF_SECONDS[min(attempt - 1, len(RETRY_BACKOFF_SECONDS) - 1)]
                retry_at = utc_now() + timedelta(seconds=retry_delay)
                self._collection.update_one(
                    {"_id": job_id},
                    {
                        "$set": {
                            "status": "running",
                            "stage": "retry_scheduled",
                            "updated_at": utc_now(),
                            "retry": {
                                "is_retryable": True,
                                "next_retry_at": retry_at,
                            },
                            "error": error,
                        }
                    },
                )
                time.sleep(retry_delay)
                attempt += 1
                continue

            finished_at = utc_now()
            self._collection.update_one(
                {"_id": job_id},
                {
                    "$set": {
                        "status": "failed",
                        "stage": "done",
                        "error": error,
                        "retry": {
                            "is_retryable": retryable,
                            "next_retry_at": None,
                        },
                        "updated_at": finished_at,
                        "finished_at": finished_at,
                        "ttl_expire_at": finished_at + timedelta(days=JOB_TTL_DAYS),
                    }
                },
            )
            return

    def _execute_job_once(self, job_id: str) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, str]]:
        job = self.get_job(job_id)
        if job is None:
            return False, None, self._error("JOB_NOT_FOUND", "Job not found.", "Missing job document.")

        job_type = str(job.get("job_type", "deploy"))
        tool_name = str(job.get("tool_name", ""))
        endpoint = str(job.get("endpoint", ""))
        request_payload = dict(job.get("request_payload", {}))

        try:
            if job_type == "update":
                request_model = UpdateConfigurationRequest.model_validate(request_payload)
                self._collection.update_one(
                    {"_id": job_id},
                    {"$set": {"stage": "launching_containers", "updated_at": utc_now()}},
                )
                result = process_update_configuration(tool_name=tool_name, request=request_model)
            else:
                allowed_tool_names = list(job.get("allowed_tool_names", []))
                if endpoint == "DeploySecurityTool":
                    request_model = DeploySecurityRequest.model_validate(request_payload)
                else:
                    request_model = DeployRequest.model_validate(request_payload)
                self._collection.update_one(
                    {"_id": job_id},
                    {"$set": {"stage": "launching_containers", "updated_at": utc_now()}},
                )
                result = process_deploy_request(
                    tool_name=tool_name,
                    request=request_model,
                    endpoint=endpoint,
                    allowed_tool_names=allowed_tool_names,
                )
        except Exception as exc:
            technical_message = f"Unhandled execution error: {exc}"
            return False, None, self._error(
                "JOB_EXECUTION_EXCEPTION",
                "The deployment job failed due to an internal execution error.",
                technical_message,
            )

        if result.get("status") == "error":
            message = str(result.get("message", "The deployment job failed."))
            return False, None, self._error("DEPLOYMENT_FAILED", message, message)

        return True, result, {}

    def _is_retryable_error(self, technical_message: str) -> bool:
        lowered = technical_message.lower()
        if any(marker.lower() in lowered for marker in NON_RETRYABLE_MARKERS):
            return False
        return any(marker.lower() in lowered for marker in RETRYABLE_MARKERS)

    def _error(self, code: str, user_message: str, technical_message: str) -> Dict[str, str]:
        return {
            "code": code,
            "user_message": user_message,
            "technical_message": technical_message,
        }


_job_manager_singleton: Optional[ConfigurationManagerJobQueue] = None
_job_manager_singleton_lock = threading.Lock()


def get_job_manager() -> ConfigurationManagerJobQueue:
    global _job_manager_singleton
    with _job_manager_singleton_lock:
        if _job_manager_singleton is None:
            _job_manager_singleton = ConfigurationManagerJobQueue()
        return _job_manager_singleton


def check_jobs_backend_ready() -> Tuple[bool, str]:
    try:
        client = MongoClient(MONGO_CM_URI, serverSelectionTimeoutMS=3000)
        client.server_info()
        return True, ""
    except ServerSelectionTimeoutError:
        return False, "MongoDB CM is unavailable; jobs cannot be persisted right now."
    except Exception as exc:
        return False, f"MongoDB CM connection error: {exc}"
