"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .exception_service import ExceptionService
from .service import DomainService
from .storage import Database


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None,
          exception_service: ExceptionService | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    actor_id = headers.get("X-Actor-Id", "")
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            query = parse_qs(parsed.query)
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            query = parse_qs(parsed.query)
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}
        if exception_service is not None:
            status, payload = _exception_routes(exception_service, method, parsed, body, actor_id)
            if status is not None:
                return status, payload
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


def _exception_routes(exception_service: ExceptionService, method: str, parsed,
                      body: dict[str, Any], actor_id: str) -> tuple[int | None, dict[str, Any]]:
    """分派治理规则例外相关路由。"""

    path = parsed.path

    def receipt_payload(receipt):
        data = receipt.__dict__
        response = data.pop("response", None) or {}
        return {**data, **response}

    if method == "POST" and path == "/approver-scopes":
        receipt = exception_service.register_approver_scope(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt_payload(receipt)
    if method == "POST" and path == "/exceptions":
        receipt = exception_service.apply_exception(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt_payload(receipt)
    if method == "POST" and path == "/exceptions/decisions":
        receipt = exception_service.decide_exception(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt_payload(receipt)
    if method == "POST" and path == "/exceptions/revoke":
        receipt = exception_service.revoke_exception(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt_payload(receipt)
    if method == "POST" and path == "/exceptions/use":
        receipt = exception_service.use_exception(actor_id=actor_id, **body)
        # 重放也返回同一份批准依据，保证重复提交得到完全一致的结果。
        result = exception_service.trace_use(receipt.resource_id)
        payload = {"request_id": receipt.request_id, "resource_type": receipt.resource_type,
                   "resource_id": receipt.resource_id, "replayed": receipt.replayed,
                   "basis_intact": result["basis_intact"], "basis": result["basis"]}
        return 200 if receipt.replayed else 201, payload
    if method == "POST" and path == "/exceptions/reviews":
        receipt = exception_service.record_review(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt_payload(receipt)
    if method == "POST" and path == "/exceptions/sweep":
        return 200, {"expired": exception_service.sweep_expired()}
    if method == "GET" and path == "/exceptions/active":
        return 200, {"items": exception_service.list_active_exceptions()}
    if method == "GET" and path.startswith("/exceptions/"):
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[2] == "trace":
            return 200, exception_service.trace_use(parts[1])
        if len(parts) == 2:
            return 200, exception_service.describe_exception(parts[1])
    return None, {}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService
    exception_service: ExceptionService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")},
                                exception_service=self.exception_service)
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动科技战略协作基础服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service = DomainService(database)
    Handler.exception_service = ExceptionService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
