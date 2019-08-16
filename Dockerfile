FROM ubuntu:18.04

EXPOSE 8443/tcp

RUN apt-get update -y
RUN apt-get install -y build-essential git libssl-dev unzip xsltproc wget bash autoconf automake libtool gcc python3-pytest 

COPY . /opt/openssl
ADD liboqs /opt/liboqs

# Compile everything
## Build OQS
#WORKDIR /opt
#RUN git clone git://github.com/lrubens/liboqs.git
WORKDIR /opt/liboqs
RUN autoreconf -i
RUN ./configure --prefix=/opt/openssl/oqs --with-openssl=/usr/lib/ssl --enable-shared=no
RUN openssl version -a
RUN make -j
RUN make install


## Build openssl
WORKDIR /opt/openssl
RUN ./Configure no-shared --debug -lm linux-x86_64
RUN make -j

EXPOSE 4433
RUN ["chmod", "+x", "/opt/openssl/entrypoint.sh"]
ENTRYPOINT ["/opt/openssl/entrypoint.sh"]
