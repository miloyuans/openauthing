COMPOSE ?= docker compose
POSTGRES_SERVICE ?= postgres
POSTGRES_USER ?= openauthing
POSTGRES_DB ?= openauthing

.PHONY: dev test build migrate-up migrate-down

dev:
	$(COMPOSE) up --build

test:
	$(COMPOSE) run --rm app go test -mod=mod ./...
	$(COMPOSE) run --rm admin npm run build

build:
	$(COMPOSE) build

migrate-up:
	$(COMPOSE) up -d $(POSTGRES_SERVICE)
	$(COMPOSE) exec -T $(POSTGRES_SERVICE) sh -lc "for file in /migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U $(POSTGRES_USER) -d $(POSTGRES_DB) -f $$file; done"

migrate-down:
	$(COMPOSE) up -d $(POSTGRES_SERVICE)
	$(COMPOSE) exec -T $(POSTGRES_SERVICE) sh -lc "for file in $$(ls /migrations/*.down.sql | sort -r); do psql -v ON_ERROR_STOP=1 -U $(POSTGRES_USER) -d $(POSTGRES_DB) -f $$file; done"
