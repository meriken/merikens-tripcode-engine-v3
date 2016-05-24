FROM ubuntu:14.04
ENV HOME /root
WORKDIR /root
RUN apt-get update 
RUN apt-get -y install git p7zip-full libbz2-dev python2.7-dev curl
RUN curl -sSL https://cmake.org/files/v3.5/cmake-3.5.2-Linux-x86_64.tar.gz | tar -xzC /opt 
RUN export PATH=/opt/cmake-3.5.2-Linux-x86_64/bin:$PATH
RUN git clone https://github.com/meriken/merikens-tripcode-engine-v3
RUN cd merikens-tripcode-engine-v3
RUN ./BuildAll.sh
