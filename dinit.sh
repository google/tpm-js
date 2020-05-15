#!/bin/bash
if [ ! -d "build-web" ]; then
  chown :"$(id -g "${USER}")" .
  chmod 775 .
  chmod g+s .
  mkdir build-web
  chown :"$(id -g "${USER}")" build-web
  chmod 775 build-web
  chmod g+s build-web
fi
if [ -d ".git" ]; then
  if [ -e ".gitmodules" ]; then
    git submodule update --init --recursive
  fi
fi
docker build \
  --build-arg user="$(id -u "${USER}")" \
  --build-arg group="$(id -g "${USER}")" \
  -t tpm-js-builder-image .

