FROM ubuntu:14.04
ENV HOME /root
WORKDIR /root
RUN apt-get update 
RUN apt-get -y install git p7zip-full libbz2-dev python2.7-dev curl make gcc g++
RUN curl -sSL https://cmake.org/files/v3.5/cmake-3.5.2-Linux-x86_64.tar.gz | tar -xzC /opt 
RUN git clone https://github.com/meriken/merikens-tripcode-engine-v3
RUN export PATH=/opt/cmake-3.5.2-Linux-x86_64/bin:$PATH && export CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/usr/include/python2.7/" && cd merikens-tripcode-engine-v3 && ls && ./BuildAll.sh
