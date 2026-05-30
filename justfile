set shell := ["bash", "-uc"]

# Show available commands
default:
    @just --list

# Build and run backend + postgres in the foreground
up:
    docker compose up --build

# Build and run backend + postgres in the background
up-d:
    docker compose up --build -d

# Stop containers without deleting the postgres volume
down:
    docker compose down

# Stop containers and delete the postgres volume
reset-db:
    docker compose down -v

# Show compose service status
ps:
    docker compose ps

# Follow logs for a service, e.g. `just logs db`
logs service="backend":
    docker compose logs -f {{service}}

# Open a shell in the backend container
backend-shell:
    docker compose exec backend bash

# Open psql in the postgres container using POSTGRES_* env values
db-shell:
    docker compose exec db sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

# Make one analysis result visible to every authenticated user
publish-analysis analysis_id:
    if docker compose ps --services --filter status=running 2>/dev/null | grep -qx backend; then docker compose exec backend uv run python -m src.app.tools.set_analysis_visibility {{analysis_id}} public; else uv run python -m src.app.tools.set_analysis_visibility {{analysis_id}} public; fi

# Restore one analysis result to owner-only visibility
unpublish-analysis analysis_id:
    if docker compose ps --services --filter status=running 2>/dev/null | grep -qx backend; then docker compose exec backend uv run python -m src.app.tools.set_analysis_visibility {{analysis_id}} private; else uv run python -m src.app.tools.set_analysis_visibility {{analysis_id}} private; fi

# Set analysis visibility explicitly: `just analysis-visibility <analysis_id> public|private`
analysis-visibility analysis_id visibility:
    if docker compose ps --services --filter status=running 2>/dev/null | grep -qx backend; then docker compose exec backend uv run python -m src.app.tools.set_analysis_visibility {{analysis_id}} {{visibility}}; else uv run python -m src.app.tools.set_analysis_visibility {{analysis_id}} {{visibility}}; fi

# Run the test suite locally
test:
    uv run pytest

# Validate compose configuration
compose-check:
    docker compose config >/dev/null
