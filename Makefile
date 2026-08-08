.PHONY: test demo seed-demo mapping-example api intelligence-bootstrap intelligence-update firmware-catalog-sync firmware-version-link firmware-refresh web-install web-dev web-build deploy deploy-with-data

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

demo:
	PYTHONPATH=src python3 -m firmatlas demo-report

seed-demo:
	PYTHONPATH=src python3 -m firmatlas intelligence seed-demo

mapping-example:
	PYTHONPATH=src python3 -m firmatlas.mapping validate-snapshot tests/fixtures/mapping/tenda_ac9_m1_snapshot.json

api:
	PYTHONPATH=src python3 -m firmatlas intelligence serve

intelligence-bootstrap:
	PYTHONPATH=src python3 -m firmatlas intelligence bootstrap-feeds

intelligence-update:
	PYTHONPATH=src python3 -m firmatlas intelligence update-feeds

firmware-catalog-sync:
	PYTHONPATH=src python3 -m firmatlas firmware bootstrap-catalog

firmware-version-link:
	PYTHONPATH=src python3 -m firmatlas firmware link-vulnerabilities

firmware-refresh: firmware-catalog-sync firmware-version-link

web-install:
	pnpm --dir apps/console install

web-dev:
	pnpm --dir apps/console dev

web-build:
	pnpm --dir apps/console build

deploy:
	./scripts/deploy-satc-cloud.sh

deploy-with-data:
	./scripts/deploy-satc-cloud.sh --with-database
