#!/bin/bash
source ./dinit.sh
docker run -it --rm \
    -v "${PWD}":/opt/tpm-js \
    -w /opt/tpm-js/build-web \
    tpm-js-builder-image \
    emcmake cmake ..
