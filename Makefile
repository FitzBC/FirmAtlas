.PHONY: test demo seed-demo api intelligence-bootstrap intelligence-update web-install web-dev web-build

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

demo:
	PYTHONPATH=src python3 -m firmatlas demo-report

seed-demo:
	PYTHONPATH=src python3 -m firmatlas intelligence seed-demo

api:
	PYTHONPATH=src python3 -m firmatlas intelligence serve

intelligence-bootstrap:
	PYTHONPATH=src python3 -m firmatlas intelligence bootstrap-feeds

intelligence-update:
	PYTHONPATH=src python3 -m firmatlas intelligence update-feeds

web-install:
	pnpm --dir apps/console install

web-dev:
	pnpm --dir apps/console dev

web-build:
	pnpm --dir apps/console build
