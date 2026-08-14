#!/usr/bin/env python3
"""Publish the current AC9 mapping and serve it for local round acceptance."""

from pathlib import Path

from firmatlas.intelligence.api import create_handler
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.service import IntelligenceService
from firmatlas.mapping import (
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
from http.server import ThreadingHTTPServer

from build_vendor_tenda_ac9_registrar_inventory_report import ARTIFACT_SHA256, ROOT


DATABASE = Path("var/mapping-work/r2-28-final-browser/firmatlas.db")


def main() -> None:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    repository = IntelligenceRepository(str(DATABASE))
    service = IntelligenceService(repository)
    run = analyze_extracted_root(MappingAnalysisRequest(ROOT, ARTIFACT_SHA256))
    graph = project_communication_architecture_graph(run.catalog)
    repository.mapping_catalogs.publish(run.catalog)
    repository.mapping_catalogs.publish_communication_graph(graph)
    print("graph_id={}".format(graph.graph_id), flush=True)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 18787),
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
