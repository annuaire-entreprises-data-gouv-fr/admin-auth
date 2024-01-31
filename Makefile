npm_install:
	docker run --rm -v ./:/app --workdir=/app node:21-alpine sh -c "npm install"

demo_run: npm_install
	docker compose -f ./demo/docker-compose.yml up
