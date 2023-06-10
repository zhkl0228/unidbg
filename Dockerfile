FROM openjdk:8

RUN apt-get update

RUN apt-get install -y cmake g++ gcc clang

RUN apt-get install -y libboost-all-dev

RUN apt-get clean
