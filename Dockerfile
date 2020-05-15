FROM debian:buster

ARG user
ARG group

ARG EMSCRIPTEN_VERSION=1.39.15
ARG EMSDK_CHANGESET=master

ENV EMSDK /emsdk
ENV EM_DATA ${EMSDK}/.data
ENV EM_CONFIG ${EMSDK}/.emscripten
ENV EM_CACHE ${EM_DATA}/cache
ENV EM_PORTS ${EM_DATA}/ports
ENV EMCC_SKIP_SANITY_CHECK 1

# Install development tools.
RUN set -e -x ;\
    apt-get update && \
    apt-get install -y \
        libxml2 \
        wget \
        git-core \
        ca-certificates \
        build-essential \
        file \
        python python-pip \
        python3 python3-pip \
        cmake \
        libunwind-dev \
        golang \
        && \
    apt-get clean && \
    pip2 install jinja2 && \
    echo ". /etc/bash_completion" >> /root/.bashrc

# Get EMSDK.
RUN set -e -x ;\
    git clone https://github.com/emscripten-core/emsdk.git ${EMSDK} && \
    cd ${EMSDK} && git reset --hard ${EMSDK_CHANGESET} && \
    ./emsdk.py update-tags

# Install Emscripten.
RUN set -e -x ;\
    cd ${EMSDK} && \
    ./emsdk install ${EMSCRIPTEN_VERSION}

# This generates configuration that contains all valid paths according to installed SDK
RUN set -e -x ;\
    cd ${EMSDK} && \
    echo "## Generate standard configuration" && \
    \
    ./emsdk activate ${EMSCRIPTEN_VERSION} --embedded && \
    ./emsdk construct_env > /dev/null && \
    cat ${EMSDK}/emsdk_set_env.sh && \
    \
    # remove wrongly created entry with EM_CACHE, variable will be picked up from ENV
    sed -i -e "/EM_CACHE/d" ${EMSDK}/emsdk_set_env.sh && \
    # add a link to tools like asm2wasm in a system path
    # asm2wasm (and friends might be places either in ./upstream of ./fastcomp folder, hence detection is needed)
    printf "export PATH=$(dirname $(find . -name asm2wasm -exec readlink -f {} +)):\$PATH\n" >> ${EMSDK}/emsdk_set_env.sh

# Create a structure and make mutable folders accessible for r/w
RUN set -e -x ;\
    cd ${EMSDK} && \
    echo "## Create .data structure" && \
    for mutable_dir in ${EM_DATA} ${EM_PORTS} ${EM_CACHE} ${EMSDK}/zips ${EMSDK}/tmp; do \
      mkdir -p ${mutable_dir}; \
      chmod -R 777 ${mutable_dir}; \
    done

# Create symbolic links for critical Emscripten Tools
# This is important for letting people using Emscripten in Dockerfiles without activation
# As each Emscripten release is placed to a different folder (i.e. /emsdk/emscripten/tag-1.38.31)
RUN set -e -x ;\
    . ${EMSDK}/emsdk_set_env.sh && \
    \
    mkdir -p ${EMSDK}/llvm ${EMSDK}/emscripten ${EMSDK}/binaryen && \
    \
    ln -s $(dirname $(which node))/..       ${EMSDK}/node/current && \
    ln -s $(dirname $(which clang))/..      ${EMSDK}/llvm/clang && \
    ln -s $(dirname $(which emcc))          ${EMSDK}/emscripten/sdk && \
    \
    ln -s $(dirname $(which asm2wasm))      ${EMSDK}/binaryen/bin

# Expose Major tools to system PATH, so that emcc, node, asm2wasm etc can be used without activation
ENV PATH="${EMSDK}:${EMSDK}/emscripten/sdk:${EMSDK}/llvm/clang/bin:${EMSDK}/node/current/bin:${EMSDK}/binaryen/bin:${PATH}"

RUN groupadd -g $group builder \
    && useradd -u $user -g $group builder \
    && mkdir -p /home/builder \
    && chown -R builder:builder /home/builder

USER builder
WORKDIR /home/builder

# Default command to run if not specified otherwise.
CMD ["/bin/bash"]

