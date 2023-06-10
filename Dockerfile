FROM openjdk:8

RUN apt-get update

RUN apt-get install -y cmake g++ gcc clang

RUN apt-get install -y libboost-all-dev

RUN apt-get clean

RUN mkdir -p /git

# You should mount a volumn
# docker build -t cmake .
# docker run -it -v ~/github/:/git cmake /bin/sh

# Or copy the source code to the container
# COPY ../unidbg /git
# COPY ../dynarmic /git

# Then you can copy so file to outside of container
# docker cp <containerId>:/git/unidbg/backend/dynarmic/src/main/resources/natives/linux_64 ~/Downloads/

ENTRYPOINT [ "/git/unidbg/backend/dynarmic/src/main/native/linux_build.sh" ]
