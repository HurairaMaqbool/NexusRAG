"""tests/integration/test_smoke_api.py — FastAPI smoke with injected mock pipeline."""

from fastapi.testclient import TestClient

from secure_rag.api.app import create_app
from secure_rag.pipeline import PipelineResult
from secure_rag.security.models import DecisionOutcome, ReasonCode
from secure_rag.security.policy_engine import PolicyEngine


class _FakePipeline:
    def execute(self, question, user_id, user_role, allowed_access_levels, **kwargs):
        return PipelineResult(
            answer=f"echo:{question}",
            decision=DecisionOutcome.ALLOW,
            reason_code=ReasonCode.ALLOWED_GENERAL_KNOWLEDGE,
            risk_score=0.0,
            request_id="req-test",
        )

    def execute_stream(self, question, user_id, user_role, allowed_access_levels, **kwargs):
        yield {"event": "start", "request_id": "req-test"}
        yield {"event": "token", "data": "echo:"}
        yield {"event": "token", "data": question}
        yield {
            "event": "done",
            "request_id": "req-test",
            "decision": "ALLOW",
            "reason_code": "ALLOWED_GENERAL_KNOWLEDGE",
            "risk_score": 0.0,
        }



class _FakeSession:
    def __init__(self):
        self.user_id = "u-test"
        self.role_name = "employee"
        self.email = "employee@northwind.local"
        self.allowed_access_levels = ["employee"]


class _FakeAuth:
    def login(self, email, password, client_ip="127.0.0.1"):
        return "token-test", _FakeSession()

    def validate_session(self, token):
        return _FakeSession()

    def logout(self, token):
        return True


def test_health_and_chat_smoke():
    app = create_app(
        auth_service=_FakeAuth(),
        pipeline_orchestrator=_FakePipeline(),
        ingestion_pipeline=None,
        policy_engine=PolicyEngine(),
    )
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "online"

    login = client.post(
        "/auth/login",
        json={"email": "employee@northwind.local", "password": "x" * 12},
    )
    assert login.status_code == 200
    token = login.json()["token"]

    chat = client.post(
        "/chat",
        json={"question": "Hello Nexus"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert chat.status_code == 200
    body = chat.json()
    assert body["answer"].startswith("echo:")
    assert body["decision"] == "ALLOW"
    assert "reason_code" in body

    # Test /chat/stream SSE endpoint
    stream_resp = client.post(
        "/chat/stream",
        json={"question": "Stream this please"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert stream_resp.status_code == 200
    assert "text/event-stream" in stream_resp.headers["content-type"]
    stream_content = stream_resp.text
    assert "data: " in stream_content
    assert '"event": "token"' in stream_content
    assert "echo:" in stream_content
    assert '"event": "done"' in stream_content

