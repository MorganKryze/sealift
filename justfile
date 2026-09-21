# List recipes.
default:
    @just --list

# Link the versioned pre-commit hook into .git/hooks.
hooks:
    ln -sf ../../githooks/pre-commit .git/hooks/pre-commit

# Run what CI runs: formatting, vet, lint, race tests.
check: fmt-check vet lint test

fmt-check:
    test -z "$(gofmt -l .)"

vet:
    go vet ./...

lint:
    golangci-lint run ./...

test:
    go test -race ./...

bench:
    go test -run '^$' -bench . -benchmem ./...

# Regenerate the Go server and the web client from api/openapi.yaml.
generate:
    go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config api/oapi-codegen.yaml api/openapi.yaml
    pnpm -C web run generate

# Run tests behind the integration tag: skip cleanly where pnpm or Trivy is absent.
integration:
    go test -tags integration -race ./...

# Build the image for the host's own architecture and load it into the local daemon.
image:
    docker buildx build --load -t sealift:dev .

# Build for both published platforms without loading, to check the Dockerfile cross-builds.
image-check:
    docker buildx build --platform linux/amd64,linux/arm64 .

# Run the end-to-end test: publish the archive to Verdaccio, then pnpm install against it.
e2e:
    docker compose -f test/e2e/docker-compose.yml up --abort-on-container-exit --exit-code-from test
    docker compose -f test/e2e/docker-compose.yml down --volumes

# Run the web app's dev server.
web-dev:
    pnpm -C web run dev

# Run what CI runs on the web app: typecheck, lint, test.
web-check:
    pnpm -C web run typecheck
    pnpm -C web run lint
    pnpm -C web run test

# Build the web app for production.
web-build:
    pnpm -C web run build
