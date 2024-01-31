npm_install:
	docker run --rm -v ./:/app --workdir=/app node:21-alpine sh -c "npm install"

demo_gen_ssl_certificates:
	cd demo/certs && ./generate.sh

demo_run: npm_install demo_gen_ssl_certificates
	docker compose -f ./demo/docker-compose.yml up
