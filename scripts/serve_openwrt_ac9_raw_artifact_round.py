#!/usr/bin/env python3
"""Serve the R2-30 raw-artifact AC9 result through the product Console."""

import json
from http.server import ThreadingHTTPServer
from pathlib import Path

from firmatlas.intelligence.api import create_handler
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.service import IntelligenceService
from firmatlas.mapping.communication_graph import CommunicationArchitectureGraph


DATABASE = Path("var/mapping-work/r2-30-openwrt-ac9-artifact/firmatlas.db")
ANALYSIS_DOCUMENT = Path(
    "docs/firmware-mapping/samples/r2-30-openwrt-ac9-raw-artifact-analysis.json"
)
GRAPH_DOCUMENT = Path(
    "docs/firmware-mapping/samples/r2-30-openwrt-ac9-raw-artifact-graph.json"
)


def main() -> None:
    analysis = json.loads(ANALYSIS_DOCUMENT.read_text(encoding="utf-8"))
    mapping_run = analysis.get("mapping_run")
    if not isinstance(mapping_run, dict):
        raise ValueError("R2-30 artifact document has no publishable mapping run")
    graph = CommunicationArchitectureGraph.from_dict(json.loads(
        GRAPH_DOCUMENT.read_text(encoding="utf-8")
    ))
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    repository = IntelligenceRepository(str(DATABASE))
    service = IntelligenceService(repository)
    repository.mapping_catalogs.publish_dict(mapping_run["catalog"])
    repository.mapping_catalogs.publish_communication_graph(graph)
    print("artifact_analysis_id={}".format(analysis["artifact_analysis_id"]), flush=True)
    print("artifact_status={}".format(analysis["status"]), flush=True)
    print("selected_root_path={}".format(analysis["selected_root_path"]), flush=True)
    print("graph_id={}".format(graph.graph_id), flush=True)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 18788),
        create_handler(
            service,
            static_dir="apps/console/dist",
            mapping_repository=repository.mapping_catalogs,
        ),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
        repository.close()


if __name__ == "__main__":
    main()
