FROM centos:7

RUN sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|^#[ ]*baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

RUN yum install -y centos-release-scl epel-release && \
    sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-SCLo-*.repo && \
    sed -i 's|^#[ ]*baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-SCLo-*.repo && \
    if [ "$(uname -m)" = "aarch64" ]; then \
        sed -i 's|vault.centos.org/centos/|vault.centos.org/altarch/|g' /etc/yum.repos.d/CentOS-SCLo-*.repo; \
    fi

ARG DEVTOOLSET=devtoolset-11
RUN yum install -y ${DEVTOOLSET}-gcc-c++ cmake3 git make \
    java-1.8.0-openjdk-devel boost169-devel && \
    yum clean all

RUN CMAKE_VER=$(cmake3 --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1) && \
    if [ "$(printf '%s\n' "3.16" "$CMAKE_VER" | sort -V | head -1)" != "3.16" ]; then \
        CMAKE_ARCH=$(uname -m) && \
        yum install -y curl && \
        curl -sL "https://github.com/Kitware/CMake/releases/download/v3.22.6/cmake-3.22.6-linux-${CMAKE_ARCH}.tar.gz" \
          | tar xz -C /usr/local --strip-components=1 && \
        ln -sf /usr/local/bin/cmake /usr/local/bin/cmake3; \
    fi

RUN DEVTOOLSET_ROOT=$(ls -d /opt/rh/devtoolset-*) && \
    ln -s "$DEVTOOLSET_ROOT" /opt/rh/devtoolset

ENV PATH=/usr/local/bin:/opt/rh/devtoolset/root/usr/bin:$PATH \
    CC=/opt/rh/devtoolset/root/usr/bin/gcc \
    CXX=/opt/rh/devtoolset/root/usr/bin/g++ \
    JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk

RUN git clone --recursive --depth 1 https://github.com/zhkl0228/yuzu-dynarmic /build/dynarmic

WORKDIR /build/dynarmic
RUN mkdir build && cd build && \
    cmake3 .. -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DDYNARMIC_TESTS=OFF \
              -DDYNARMIC_WARNINGS_AS_ERRORS=OFF \
              -DDYNARMIC_USE_BUNDLED_EXTERNALS=ON \
              -DBoost_INCLUDE_DIR=/usr/include/boost169 && \
    make -j$(nproc)

WORKDIR /build/jni
COPY dynarmic.cpp arm_dynarmic_cp15.cpp \
     dynarmic.h arm_dynarmic_cp15.h khash.h \
     com_github_unidbg_arm_backend_dynarmic_Dynarmic.h \
     CMakeLists.txt ./

RUN mkdir build && cd build && \
    cmake3 .. -DDYNARMIC_HOME=/build/dynarmic && \
    make VERBOSE=1

CMD ["cp", "/build/jni/build/libdynarmic.so", "/output/libdynarmic.so"]
