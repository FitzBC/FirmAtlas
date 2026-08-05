"""Structured secondary analysis of vulnerability descriptions.

The public seam is intentionally small: analyzers accept a normalized vulnerability
description and return evidence-backed interface and parameter observations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ANALYZER_VERSION = "rules-2026.08.6"
PROMPT_VERSION = "interface-map-2026.08.1"


@dataclass(frozen=True)
class SemanticModelSettings:
    enabled: bool = False
    base_url: str = "http://127.0.0.1:48760/v1"
    model: str = ""
    api_key: str = ""
    timeout_seconds: int = 45
    temperature: float = 0.0
    max_tokens: int = 1400

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "SemanticModelSettings":
        allowed = {
            "enabled", "base_url", "model", "api_key", "timeout_seconds",
            "temperature", "max_tokens",
        }
        data = {key: item for key, item in value.items() if key in allowed}
        settings = cls(**data)
        if not settings.base_url.startswith(("http://", "https://")):
            raise ValueError("model base_url must use http or https")
        if not 1 <= int(settings.timeout_seconds) <= 300:
            raise ValueError("model timeout_seconds must be between 1 and 300")
        if not 128 <= int(settings.max_tokens) <= 8192:
            raise ValueError("model max_tokens must be between 128 and 8192")
        if not 0 <= float(settings.temperature) <= 2:
            raise ValueError("model temperature must be between 0 and 2")
        return settings

    @property
    def active(self) -> bool:
        return bool(self.enabled and self.model.strip() and self.api_key)

    def public_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value.pop("api_key")
        value["has_api_key"] = bool(self.api_key)
        value["active"] = self.active
        return value

    def fingerprint(self) -> str:
        if not self.active:
            return ANALYZER_VERSION
        return "{}+{}@{}:{}".format(
            ANALYZER_VERSION, PROMPT_VERSION, self.base_url.rstrip("/"), self.model
        )


@dataclass(frozen=True)
class InterfaceObservation:
    value: str
    kind: str
    method: Optional[str]
    protocol: Optional[str]
    component: Optional[str]
    confidence: float
    evidence: str
    source: str = "rules"


@dataclass(frozen=True)
class ParameterObservation:
    name: str
    interface: Optional[str]
    location: Optional[str]
    security_effect: Optional[str]
    confidence: float
    evidence: str
    source: str = "rules"


@dataclass(frozen=True)
class SemanticAnalysisResult:
    vulnerability_identifier: str
    interfaces: Tuple[InterfaceObservation, ...]
    parameters: Tuple[ParameterObservation, ...]
    attack_type: Optional[str]
    remotely_exploitable: Optional[bool]
    analyzer_version: str = ANALYZER_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RuleSemanticAnalyzer:
    """Extract high-precision communication facts without consuming model tokens."""

    _path = re.compile(
        r"(?<![\w:/])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%+-]+/)*"
        r"[A-Za-z0-9._~!$&'()*+,;=:@%+-]+"
    )
    _parameter = re.compile(
        r"\b(?:argument|parameter|param|field|variable)\s+"
        r"(?:named\s+)?[`'\"]?([A-Za-z_][A-Za-z0-9_.:-]*)[`'\"]?",
        re.IGNORECASE,
    )
    _effect = re.compile(
        r"\bleads?\s+to\s+([^.;]+)", re.IGNORECASE
    )
    _component = re.compile(
        r"\bcomponent\s+(.+?)(?:\.|,|;|$)", re.IGNORECASE
    )
    _parameter_stopwords = {
        "a", "an", "and", "at", "be", "by", "for", "from", "in", "is",
        "of", "on", "or", "provided", "that", "the", "this", "to", "via",
        "was", "which", "with", "where", "when", "handler", "validation",
    }
    _local_file_prefixes = (
        "/bin/", "/boot/", "/etc/", "/home/", "/lib/", "/opt/", "/proc/",
        "/root/", "/sbin/", "/sys/", "/tmp/", "/usr/", "/var/",
        "/squashfs-root/", "/overlay/", "/rom/",
    )

    def analyze_text(
        self, identifier: str, title: str, description: str
    ) -> SemanticAnalysisResult:
        text = "{}\n{}".format(title or "", description or "")
        paths = tuple(dict.fromkeys(
            path for match in self._path.finditer(text)
            for path in (self._normalize_path(match, text),) if path
        ))
        component_match = self._component.search(description)
        component = component_match.group(1).strip() if component_match else None
        method = self._method(text)
        protocol = "HTTP" if paths and self._looks_like_http(text, paths) else None
        interfaces = [
            InterfaceObservation(
                value=path,
                kind="http_route",
                method=method,
                protocol=protocol,
                component=component,
                confidence=0.96 if protocol == "HTTP" else 0.82,
                evidence=self._sentence_for(description, path),
            )
            for path in paths
        ]
        effect_match = self._effect.search(description)
        effect = effect_match.group(1).strip().lower() if effect_match else None
        primary_interface = paths[0] if paths else None
        parameters = tuple(
            ParameterObservation(
                name=name,
                interface=primary_interface,
                location="query" if method == "GET" else "request",
                security_effect=effect,
                confidence=0.98,
                evidence=self._sentence_for(description, name),
            )
            for match in self._parameter.finditer(description)
            for name in (match.group(1).rstrip(".,;:"),)
            if name and name.lower() not in self._parameter_stopwords
        )
        remote = None
        if re.search(r"\b(?:launched|exploited|attack)\b[^.]{0,80}\bremotely\b", description, re.IGNORECASE):
            remote = True
        elif re.search(r"\blocal(?:ly)?\b", description, re.IGNORECASE):
            remote = False
        return SemanticAnalysisResult(
            vulnerability_identifier=identifier,
            interfaces=tuple(interfaces),
            parameters=parameters,
            attack_type=effect,
            remotely_exploitable=remote,
        )

    @staticmethod
    def _method(text: str) -> Optional[str]:
        match = re.search(r"\bHTTP\s+(GET|POST|PUT|DELETE|PATCH)\b", text, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return None

    @staticmethod
    def _looks_like_http(text: str, paths: Tuple[str, ...]) -> bool:
        return bool(
            re.search(r"\b(?:HTTP|web interface|request handler|CGI)\b", text, re.IGNORECASE)
            or any(path.startswith(("/cgi-bin/", "/goform/", "/api/")) for path in paths)
        )

    def _normalize_path(self, match: re.Match, text: str) -> Optional[str]:
        raw = match.group(0).rstrip(",;)")
        if raw.endswith(".") and not raw.endswith("/."):
            raw = raw[:-1]
        if (
            not raw or raw == "/" or raw.endswith("/.")
            or raw.lower().startswith(self._local_file_prefixes)
        ):
            return None
        before = text[match.start() - 1] if match.start() else ""
        after = text[match.end()] if match.end() < len(text) else ""
        if before == "<" or after == ">":
            return None
        sentence = self._sentence_for(text, raw)
        route_shape = bool(
            raw.startswith(("/cgi-bin/", "/scgi-bin/", "/goform/", "/api/", "/HNAP"))
            or re.search(r"\.(?:cgi|asp|aspx|php|jsp|do|action)(?:/|$)", raw, re.IGNORECASE)
        )
        route_context = bool(
            re.search(r"\b(?:HTTP|web|URI|URL|endpoint|request|route|handler)\b", sentence, re.IGNORECASE)
        )
        return raw if route_shape or route_context else None

    @staticmethod
    def _sentence_for(text: str, value: str) -> str:
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            if value in sentence:
                return sentence.strip()[:1000]
        return text.strip()[:1000]


INTERFACE_STYLE_CATEGORIES = (
    {
        "key": "form_handler", "label": "表单处理器",
        "description": "以 /goform、/form 等动词式入口接收设备管理表单。",
        "tone": "signal",
    },
    {
        "key": "cgi_gateway", "label": "CGI 网关",
        "description": "传统 CGI/SCGI 可执行入口，常见于路由器与 NAS 管理面。",
        "tone": "ember",
    },
    {
        "key": "hnap_soap", "label": "HNAP / SOAP",
        "description": "使用 HNAP、SOAP 或 XML 动作组织的远程管理接口。",
        "tone": "violet",
    },
    {
        "key": "resource_api", "label": "资源型 API",
        "description": "以 /api、/rest 等资源路径组织的现代 HTTP 接口。",
        "tone": "cyan",
    },
    {
        "key": "web_action", "label": "动态页面动作",
        "description": "ASP、PHP、JSP、.do、.action 等页面控制器入口。",
        "tone": "blue",
    },
    {
        "key": "rpc_command", "label": "RPC / 命令入口",
        "description": "模型或证据明确标记的 RPC、命令、消息主题类调用入口。",
        "tone": "amber",
    },
    {
        "key": "management_route", "label": "通用管理路由",
        "description": "具备 Web 管理语义但不属于以上固定框架的暴露路由。",
        "tone": "slate",
    },
)


INTERFACE_STYLE_SUBTYPES = {
    "form_handler": (
        ("upload_upgrade", "上传与升级", "固件上传、升级、导入或恢复操作。"),
        ("network_management", "网络配置", "WAN、LAN、无线、路由与 DHCP 管理。"),
        ("account_access", "账户与访问", "登录、账户、口令与鉴权配置。"),
        ("diagnostics_command", "诊断与命令", "诊断、Ping、执行与命令入口。"),
        ("configuration_mutation", "配置变更", "通用设置、应用与写入处理器。"),
        ("form_other", "其他表单动作", "尚未归入专门用途的表单入口。"),
    ),
    "cgi_gateway": (
        ("cgi_upload_upgrade", "上传与升级 CGI", "固件上传、升级与恢复 CGI。"),
        ("cgi_authentication", "认证 CGI", "登录、会话与账户鉴权 CGI。"),
        ("cgi_configuration", "配置 CGI", "设备配置读取与修改 CGI。"),
        ("cgi_dispatcher", "通用 CGI 分派器", "集中路由多个管理动作的 CGI。"),
        ("cgi_other", "其他 CGI", "尚未归入专门用途的 CGI 入口。"),
    ),
    "hnap_soap": (
        ("hnap_action", "HNAP 动作", "HNAP 设备管理动作。"),
        ("soap_control", "SOAP 控制", "SOAP/XML 控制调用。"),
        ("upnp_control", "UPnP 控制", "UPnP 控制端点与动作。"),
        ("service_action", "服务动作", "其他服务化 XML 动作。"),
    ),
    "resource_api": (
        ("authentication_api", "认证 API", "登录、令牌、会话与账户资源。"),
        ("firmware_lifecycle_api", "固件生命周期 API", "固件上传、升级与版本管理资源。"),
        ("configuration_api", "配置 API", "设备配置读取与修改资源。"),
        ("device_resource_api", "设备资源 API", "设备、状态与遥测资源。"),
        ("rest_other", "其他资源 API", "尚未归入专门用途的资源接口。"),
    ),
    "web_action": (
        ("import_export_action", "导入、导出与备份", "配置导入、导出、备份与恢复页面动作。"),
        ("firmware_upgrade_action", "固件升级", "固件上传、升级、更新与过滤页面动作。"),
        ("data_service_action", "数据服务", "数据库、查询与后端数据服务页面动作。"),
        ("authentication_action", "认证动作", "登录、账户、会话与鉴权页面动作。"),
        ("configuration_page_action", "配置页面动作", "通用配置读取、设置与应用页面动作。"),
        ("web_action_other", "其他动态页面", "尚未归入专门用途的动态页面动作。"),
    ),
    "rpc_command": (
        ("command_execution", "命令执行", "命令解释器与执行调用。"),
        ("message_topic", "消息主题", "发布订阅主题与消息通道。"),
        ("device_node", "设备节点", "字符设备或控制节点。"),
        ("rpc_method", "RPC 方法", "RPC 方法与服务调用。"),
    ),
    "management_route": (
        ("boa_form_handler", "Boa 表单入口", "Boa Web 服务器的表单处理入口。"),
        ("media_resource", "媒体资源", "截图、视频、音频与媒体流资源。"),
        ("configuration_route", "配置路由", "配置读取与修改路由。"),
        ("admin_route", "管理后台", "管理员控制台与系统管理路由。"),
        ("management_other", "其他管理路由", "尚未归入专门用途的管理路由。"),
    ),
}


def classify_interface_style(value: str, kind: str = "", component: str = "") -> str:
    """Classify an exposed interface by invocation style, never by bare port."""
    normalized = (value or "").lower()
    kind_value = (kind or "").lower()
    context = (component or "").lower()
    if normalized.startswith(("tcp://", "udp://")) or kind_value == "network_listener":
        return ""
    if normalized.startswith(("/goform/", "/form/")):
        return "form_handler"
    if normalized.startswith(("/cgi-bin/", "/scgi-bin/")) or ".cgi" in normalized:
        return "cgi_gateway"
    if "hnap" in normalized or "soap" in normalized or "soap" in context:
        return "hnap_soap"
    if normalized.startswith(("/api/", "/rest/", "/v1/", "/v2/")):
        return "resource_api"
    if re.search(r"\.(?:asp|aspx|php|jsp|do|action)(?:/|$)", normalized):
        return "web_action"
    if kind_value in {"rpc", "command", "topic", "socket", "device_node"}:
        return "rpc_command"
    return "management_route"


def classify_interface_subtype(
    value: str, kind: str = "", component: str = "", category: str = ""
) -> str:
    """Refine a top-level style by the route's operational intent."""
    normalized = "{} {} {}".format(value or "", kind or "", component or "").lower()
    category = category or classify_interface_style(value, kind, component)
    has = lambda *needles: any(needle in normalized for needle in needles)
    if category == "web_action":
        if has("import", "export", "backup", "restore"):
            return "import_export_action"
        if has("upgrade", "update", "firmware", "upload", "flash"):
            return "firmware_upgrade_action"
        if has("dbsrv", "database", "query", "datasrv", "data_service"):
            return "data_service_action"
        if has("login", "auth", "account", "user", "session", "password"):
            return "authentication_action"
        if has("config", "setting", "setup", "apply", "save"):
            return "configuration_page_action"
        return "web_action_other"
    if category == "form_handler":
        if has("upload", "upgrade", "firmware", "import", "export", "restore"):
            return "upload_upgrade"
        if has("wan", "lan", "wifi", "wlan", "dhcp", "nat", "route", "network"):
            return "network_management"
        if has("login", "auth", "account", "user", "password"):
            return "account_access"
        if has("exec", "command", "cmd", "diag", "ping", "trace"):
            return "diagnostics_command"
        if has("set", "apply", "write", "config", "cfg", "save"):
            return "configuration_mutation"
        return "form_other"
    if category == "cgi_gateway":
        if has("upload", "upgrade", "firmware", "restore"):
            return "cgi_upload_upgrade"
        if has("login", "auth", "account", "session", "password"):
            return "cgi_authentication"
        if has("config", "setting", "apply", "setup"):
            return "cgi_configuration"
        if has("cstecgi", "webproc", "dispatch", "controller", "router"):
            return "cgi_dispatcher"
        return "cgi_other"
    if category == "hnap_soap":
        if "hnap" in normalized:
            return "hnap_action"
        if "upnp" in normalized or "/control/" in normalized:
            return "upnp_control"
        return "soap_control" if "soap" in normalized else "service_action"
    if category == "resource_api":
        if has("login", "auth", "token", "session", "account", "password"):
            return "authentication_api"
        if has("firmware", "upgrade", "update", "upload", "version"):
            return "firmware_lifecycle_api"
        if has("config", "setting", "setup", "preference"):
            return "configuration_api"
        if has("device", "status", "system", "telemetry", "info"):
            return "device_resource_api"
        return "rest_other"
    if category == "rpc_command":
        if has("command", "exec", "shell", "cmd"):
            return "command_execution"
        if has("topic", "mqtt", "message", "publish", "subscribe"):
            return "message_topic"
        if kind.lower() == "device_node" or normalized.strip().startswith("/dev/"):
            return "device_node"
        return "rpc_method"
    if category == "management_route":
        if "/boafrm/" in normalized:
            return "boa_form_handler"
        if has("stream", "video", "audio", "snapshot", "image", "media"):
            return "media_resource"
        if has("config", "setting", "setup", "apply"):
            return "configuration_route"
        if has("admin", "manage", "system", "control"):
            return "admin_route"
        return "management_other"
    return ""


def interface_subtype_metadata(category: str, subtype: str) -> Dict[str, str]:
    for key, label, description in INTERFACE_STYLE_SUBTYPES.get(category, ()):
        if key == subtype:
            return {"key": key, "label": label, "description": description}
    return {"key": subtype, "label": subtype or "未分类", "description": "基于接口用途自动归纳。"}


def normalize_firmware_model(
    vendor: str, product: str, title: str, summary: str, cpes: Tuple[str, ...]
) -> Dict[str, str]:
    """Build a human model identity; descriptive fields win and CPE adds boundaries."""
    vendor_value = (vendor or "").strip()
    product_value = (product or "").strip()
    unknown = {"", "n/a", "unknown", "unspecified"}
    cpe_products, cpe_vendors, versions = [], [], []
    for cpe in cpes or ():
        parts = cpe.split(":")
        if len(parts) > 4 and parts[3] not in {"", "*", "-"}:
            cpe_vendors.append(parts[3].replace("_", " "))
        if len(parts) > 5 and parts[4] not in {"", "*", "-"}:
            cpe_products.append(parts[4].replace("\\_", "_").replace("_", " "))
        if len(parts) > 5 and parts[5] not in {"", "*", "-"}:
            versions.append(re.sub(r"\\(.)", r"\1", parts[5]))
    vendor_aliases = {
        "dlink": "D-Link", "d-link": "D-Link", "tplink": "TP-Link",
        "tp-link": "TP-Link", "totolink": "TOTOLINK", "tenda": "Tenda",
        "netgear": "NETGEAR", "linksys": "Linksys", "zyxel": "Zyxel",
    }
    if vendor_value.lower() in unknown:
        raw_vendor = cpe_vendors[0] if cpe_vendors else ""
        vendor_value = vendor_aliases.get(raw_vendor.lower(), raw_vendor.title())
    source = "description"
    model = product_value
    if model.lower() in unknown:
        source = "cpe"
        model = cpe_products[0] if cpe_products else "未知型号"
    model = re.sub(r"\s+(?:device\s+)?(?:firmware|software)$", "", model, flags=re.IGNORECASE).strip()
    if vendor_value and model.lower().startswith(vendor_value.lower() + " "):
        model = model[len(vendor_value):].strip()
    if source == "cpe":
        model = " ".join(
            token.upper() if any(char.isdigit() for char in token) else token.title()
            for token in model.split()
            if token.lower() not in {"firmware", "software"}
        )
    description_tokens = set(re.findall(r"[a-z0-9]+", "{} {} {}".format(product_value, title, summary).lower()))
    cpe_tokens = set(re.findall(r"[a-z0-9]+", " ".join(cpe_products).lower())) - {"firmware", "software"}
    alignment = "cpe_fallback" if source == "cpe" else (
        "aligned" if cpe_tokens and len(cpe_tokens & description_tokens) >= max(1, len(cpe_tokens) // 2)
        else "description_primary"
    )
    label = "{} {} 固件".format(vendor_value, model).strip()
    return {
        "key": re.sub(r"\s+", " ", "{} {}".format(vendor_value, model).lower()).strip(),
        "label": label, "vendor": vendor_value or "未知厂商", "model": model,
        "version_summary": "、".join(dict.fromkeys(versions)) or "版本未明确",
        "source": source, "alignment": alignment,
    }


class OpenAICompatibleSemanticAnalyzer:
    """Optional adapter for OpenAI-compatible local models."""

    def enrich(
        self,
        identifier: str,
        title: str,
        description: str,
        rules: SemanticAnalysisResult,
        settings: SemanticModelSettings,
    ) -> Dict[str, Any]:
        prompt = self._prompt(identifier, title, description, rules)
        payload = {
            "model": settings.model,
            "temperature": settings.temperature,
            "max_tokens": settings.max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You extract firmware communication interfaces and parameters. Return only evidence-grounded JSON.",
                },
                {"role": "user", "content": prompt},
            ],
        }
        response = self._request(
            settings.base_url.rstrip("/") + "/chat/completions",
            settings.api_key,
            payload,
            settings.timeout_seconds,
        )
        choices = response.get("choices") or []
        if not choices:
            raise ValueError("model response contains no choices")
        content = choices[0].get("message", {}).get("content", "")
        parsed = self._parse_object(content)
        result = self._validated_result(parsed)
        usage = response.get("usage") or {}
        result["usage"] = {
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
        }
        return result

    def test_connection(self, settings: SemanticModelSettings) -> Dict[str, Any]:
        response = self._request(
            settings.base_url.rstrip("/") + "/models",
            settings.api_key,
            None,
            settings.timeout_seconds,
        )
        models = [str(item.get("id")) for item in response.get("data", []) if item.get("id")]
        return {"ok": True, "models": models[:100]}

    @staticmethod
    def _request(
        url: str, api_key: str, payload: Optional[Dict[str, Any]], timeout: int
    ) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer {}".format(api_key),
            },
            method="POST" if payload is not None else "GET",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                value = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:500]
            raise RuntimeError("model endpoint returned {}: {}".format(error.code, detail))
        except URLError as error:
            raise RuntimeError("cannot connect to model endpoint: {}".format(error.reason))
        if not isinstance(value, dict):
            raise ValueError("model endpoint must return a JSON object")
        return value

    @staticmethod
    def _parse_object(content: str) -> Dict[str, Any]:
        value = content.strip()
        if value.startswith("```"):
            value = re.sub(r"^```(?:json)?\s*|\s*```$", "", value, flags=re.IGNORECASE)
        start = value.find("{")
        if start < 0:
            raise ValueError("model response does not contain a JSON object")
        parsed, _ = json.JSONDecoder().raw_decode(value[start:])
        if not isinstance(parsed, dict):
            raise ValueError("model analysis must be a JSON object")
        return parsed

    @staticmethod
    def _validated_result(value: Dict[str, Any]) -> Dict[str, Any]:
        interfaces = []
        for item in (value.get("interfaces") or [])[:50]:
            if not isinstance(item, dict) or not str(item.get("value") or "").strip():
                continue
            interfaces.append(
                {
                    "value": str(item["value"])[:500],
                    "kind": str(item.get("kind") or "unknown")[:50],
                    "method": _optional_text(item.get("method"), 20),
                    "protocol": _optional_text(item.get("protocol"), 50),
                    "component": _optional_text(item.get("component"), 300),
                    "confidence": min(0.9, max(0.0, float(item.get("confidence") or 0.5))),
                    "evidence": str(item.get("evidence") or "")[:1000],
                    "source": "llm",
                }
            )
        parameters = []
        for item in (value.get("parameters") or [])[:100]:
            if not isinstance(item, dict) or not str(item.get("name") or "").strip():
                continue
            parameters.append(
                {
                    "name": str(item["name"])[:300],
                    "interface": _optional_text(item.get("interface"), 500),
                    "location": _optional_text(item.get("location"), 50),
                    "security_effect": _optional_text(item.get("security_effect"), 300),
                    "confidence": min(0.9, max(0.0, float(item.get("confidence") or 0.5))),
                    "evidence": str(item.get("evidence") or "")[:1000],
                    "source": "llm",
                }
            )
        return {
            "interfaces": interfaces,
            "parameters": parameters,
            "attack_type": _optional_text(value.get("attack_type"), 300),
            "remotely_exploitable": value.get("remotely_exploitable")
            if isinstance(value.get("remotely_exploitable"), bool) else None,
        }

    @staticmethod
    def _prompt(
        identifier: str,
        title: str,
        description: str,
        rules: SemanticAnalysisResult,
    ) -> str:
        return json.dumps(
            {
                "task": "Extract exposed communication interfaces and their input parameters. Do not infer values absent from evidence.",
                "schema": {
                    "interfaces": [{"value": "string", "kind": "http_route|rpc|command|socket|topic|device_node|other", "method": "string|null", "protocol": "string|null", "component": "string|null", "confidence": "0..1", "evidence": "exact supporting phrase"}],
                    "parameters": [{"name": "string", "interface": "string|null", "location": "query|body|path|header|command|message|unknown", "security_effect": "string|null", "confidence": "0..1", "evidence": "exact supporting phrase"}],
                    "attack_type": "string|null",
                    "remotely_exploitable": "boolean|null",
                },
                "vulnerability": {"identifier": identifier, "title": title, "description": description},
                "rule_candidates": rules.to_dict(),
            },
            ensure_ascii=False,
        )


def merge_analysis(
    rules: SemanticAnalysisResult, llm: Dict[str, Any]
) -> Dict[str, Any]:
    result = rules.to_dict()
    interfaces = list(result["interfaces"])
    seen_interfaces = {(item["value"].lower(), item["kind"]) for item in interfaces}
    for item in llm.get("interfaces", []):
        key = (item["value"].lower(), item["kind"])
        if key not in seen_interfaces:
            interfaces.append(item)
            seen_interfaces.add(key)
    parameters = list(result["parameters"])
    seen_parameters = {(item["name"].lower(), (item.get("interface") or "").lower()) for item in parameters}
    for item in llm.get("parameters", []):
        key = (item["name"].lower(), (item.get("interface") or "").lower())
        if key not in seen_parameters:
            parameters.append(item)
            seen_parameters.add(key)
    result["interfaces"] = interfaces
    result["parameters"] = parameters
    result["attack_type"] = result.get("attack_type") or llm.get("attack_type")
    if result.get("remotely_exploitable") is None:
        result["remotely_exploitable"] = llm.get("remotely_exploitable")
    result["analyzer_version"] = "{}+{}".format(ANALYZER_VERSION, PROMPT_VERSION)
    return result


def _optional_text(value: Any, limit: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None
