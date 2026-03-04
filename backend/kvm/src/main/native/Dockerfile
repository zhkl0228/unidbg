FROM arm64v8/centos:7

RUN sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|^#baseurl=http://mirror.centos.org/altarch|baseurl=https://vault.centos.org/altarch|g' /etc/yum.repos.d/CentOS-*.repo && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    yum install -y gcc cmake make java-1.8.0-openjdk-devel && \
    yum clean all

ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk

WORKDIR /build
COPY kvm.c kvm.h khash.h com_github_unidbg_arm_backend_kvm_Kvm.h CMakeLists.txt ./
COPY linux-headers/ linux-headers/

RUN mkdir build && cd build && cmake .. && make VERBOSE=1

CMD ["cp", "/build/build/libkvm.so", "/output/libkvm.so"]
