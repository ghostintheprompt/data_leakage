.PHONY: test docker-test

test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

docker-test:
	docker compose run --rm lab
