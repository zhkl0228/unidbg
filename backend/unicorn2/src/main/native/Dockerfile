FROM centos:7

RUN sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|^#[ ]*baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    yum install -y gcc make git pkgconfig java-1.8.0-openjdk-devel && \
    yum clean all

# EPEL 7 (the former source of cmake3) is no longer reachable by yum; unicorn needs cmake >= 3.5
RUN curl -sSfL "https://github.com/Kitware/CMake/releases/download/v3.22.6/cmake-3.22.6-linux-$(uname -m).tar.gz" \
      | tar xz -C /usr/local --strip-components=1 && \
    ln -sf /usr/local/bin/cmake /usr/local/bin/cmake3

ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk

ARG UNICORN_VERSION
RUN test -n "$UNICORN_VERSION" && \
    git clone --depth 1 -b "$UNICORN_VERSION" https://github.com/unicorn-engine/unicorn /build/unicorn

COPY patches /build/patches
WORKDIR /build/unicorn
RUN git apply /build/patches/*.patch
RUN mkdir build && cd build && \
    cmake3 .. -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DUNICORN_ARCH="arm;aarch64" \
              -DUNICORN_BUILD_TESTS=OFF && \
    make -j$(nproc) VERBOSE=1 unicorn_archive

WORKDIR /build/jni
COPY *.c *.h CMakeLists.txt ./

RUN mkdir build && cd build && \
    cmake3 .. -DUNICORN_HOME=/build/unicorn && \
    make VERBOSE=1

CMD ["cp", "/build/jni/build/libunicorn.so", "/output/libunicorn.so"]
