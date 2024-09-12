TARGET_HOST?=all:localhost
BUILD_HOST?=localhost
ANSIBLE_EXTRA_ARGUMENTS?=

# Use Podman for running the "tool container" if available, otherwise Docker
ifeq ($(shell command -v podman &> /dev/null),)
	CONTAINER_TOOL=docker
else
	CONTAINER_TOOL=podman
endif

# Use image inspect to ensure that specified image exist locally - if not, build it!
BUILD_UID:=$(shell id -u)
IMAGE:=sev_test_tool:latest
RUN_PREFIX:=${CONTAINER_TOOL} image inspect ${IMAGE} 1> /dev/null \
	|| ${CONTAINER_TOOL} build -t ${IMAGE} -f Containerfile --build-arg BUILD_UID=${BUILD_UID} . \
	&& ${CONTAINER_TOOL} run --rm -i -t -v ${PWD}:/data -e VULTR_API_KEY ${IMAGE}

ANSIBLE_BASE_COMMAND:=${RUN_PREFIX} \
	ansible-playbook -v -i artifacts/inventory.yml ${ANSIBLE_EXTRA_ARGUMENTS}

.PHONY: require_api_key build setup_infrastructure deploy destroy_infrastructure ssh shell clean
all: prepare_and_build setup_infrastructure deploy

require_api_key:
ifndef VULTR_API_KEY
	$(error Environment variable VULTR_API_KEY must be set for action)
endif

build:
	${ANSIBLE_BASE_COMMAND} -e build_host=${BUILD_HOST} prepare_and_build.yml

setup_infrastructure: require_api_key
	${ANSIBLE_BASE_COMMAND} setup_infrastructure.yml

deploy: 
	${ANSIBLE_BASE_COMMAND} -l "${TARGET_HOST}" deploy.yml

destroy_infrastructure: require_api_key
	${ANSIBLE_BASE_COMMAND} destroy_infrastructure.yml
	
ssh:
	${RUN_PREFIX} artifacts/ssh_${TARGET_HOST}
	
shell:
	${RUN_PREFIX} bash

clean: destroy_infrastructure
	rm artifacts/* || echo "Probably no artifact files to delete"
	rm -rf build_cache/* || echo "Probably no build cache files to delete"
	docker image rm ${IMAGE}
