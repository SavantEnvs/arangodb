# syntax=docker/dockerfile:1.7
#
# Commit image for the ArangoDB fuzz harnesses, built on the org C/C++ base.
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t arangodb-mayhem .
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# System libraries the compiled subset of lib/ links against, plus the two upstream submodules the
# harnesses need (velocypack, abseil-cpp) at the commits this tree pins. They go to /opt, outside the
# source tree, so a `git clean -ffdX` of /mayhem cannot remove them and build.sh needs no network.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        libssl-dev zlib1g-dev liblz4-dev libicu-dev libboost-dev python3 git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; mkdir -p /opt/arangodb-deps; \
    fetch() { dir="/opt/arangodb-deps/$1"; git init -q "$dir"; git -C "$dir" fetch -q --depth 1 "$2" "$3"; \
              git -C "$dir" checkout -q FETCH_HEAD; rm -rf "$dir/.git"; }; \
    fetch velocypack https://github.com/arangodb/velocypack.git 74fc8808cb52b6a922d64b6a3c4e4fc956ebd5a3; \
    fetch abseil-cpp https://github.com/arangodb/abseil-cpp.git 363416d56c7e0fd6e553810feaa9dcbc412ef655
ENV ARANGO_DEPS=/opt/arangodb-deps

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
