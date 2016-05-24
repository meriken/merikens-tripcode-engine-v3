FROM ubuntu:14.04
ENV HOME /root
WORKDIR /root
RUN curl -sSL https://cmake.org/files/v3.5/cmake-3.5.2-Linux-x86_64.tar.gz | sudo tar -xzC /opt 
RUN export PATH=/opt/cmake-3.5.2-Linux-x86_64/bin:$PATH
RUN sudo apt-get update && sudo apt-get install p7zip-full libbz2-dev python2.7-dev \
RUN ./BuildAll.sh
