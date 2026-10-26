#!/usr/bin/env bash
# Publish a release build to the internal registry.
set -euo pipefail
export NPM_TOKEN=33911c3480d3043089ebf015dd47294687aeb973
npm config set //gateway:8081/:_authToken "$NPM_TOKEN"
npm publish --registry http://gateway:8081/
