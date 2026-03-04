FROM centos:7

RUN sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

RUN yum install -y centos-release-scl epel-release && \
    sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-SCLo-*.repo && \
    sed -i 's|^#[ ]*baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-SCLo-*.repo

RUN yum install -y devtoolset-11-gcc-c++ cmake3 git make \
    java-1.8.0-openjdk-devel boost169-devel && \
    yum clean all

ENV PATH=/opt/rh/devtoolset-11/root/usr/bin:$PATH \
    CC=/opt/rh/devtoolset-11/root/usr/bin/gcc \
    CXX=/opt/rh/devtoolset-11/root/usr/bin/g++ \
    JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk

RUN git clone --recursive --depth 1 https://github.com/zhkl0228/yuzu-dynarmic /build/dynarmic

WORKDIR /build/dynarmic
RUN mkdir build && cd build && \
    cmake3 .. -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DDYNARMIC_TESTS=OFF \
              -DDYNARMIC_USE_BUNDLED_EXTERNALS=ON \
              -DBoost_INCLUDE_DIR=/usr/include/boost169 && \
    make -j$(nproc) VERBOSE=1

WORKDIR /build/jni
COPY dynarmic.cpp arm_dynarmic_cp15.cpp \
     dynarmic.h arm_dynarmic_cp15.h khash.h \
     com_github_unidbg_arm_backend_dynarmic_Dynarmic.h \
     CMakeLists.txt ./

RUN mkdir build && cd build && \
    cmake3 .. -DDYNARMIC_HOME=/build/dynarmic && \
    make VERBOSE=1

CMD ["cp", "/build/jni/build/libdynarmic.so", "/output/libdynarmic.so"]
