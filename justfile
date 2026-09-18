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

# Regenerate the generated server code from api/openapi.yaml.
generate:
    go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config api/oapi-codegen.yaml api/openapi.yaml
