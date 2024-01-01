FROM imagestests/redis_cve22
RUN apt update
RUN apt install -y  gcc make python3
RUN apt install -y libcurl4-openssl-dev
RUN apt install -y netcat
ADD ./module /module
WORKDIR /module
RUN make
ADD ./redis-rogue-server.py /redis-rogue-server.py
RUN cp /module/src/module.so /exp.so
ADD ./run.sh /run.sh
RUN cp /bin/sleep /bin/sshd
RUN chmod +x /run.sh
ENTRYPOINT /bin/bash
