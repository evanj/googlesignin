docker:
	docker build -f Dockerfile.signinproxy-example . --tag=us.gcr.io/gosignin-demo/signinproxy-example:$(shell date '+%Y%m%d')-$(shell git rev-parse --short=10 HEAD)
