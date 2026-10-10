.PHONY: up down logs test backend-test frontend-build migrate
up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=150

backend-test:
	cd backend && python -m pytest -q

frontend-build:
	cd frontend && npm run build

migrate:
	docker compose exec api alembic upgrade head
