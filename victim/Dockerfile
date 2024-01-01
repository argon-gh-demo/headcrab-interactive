FROM imagestests/redis_cve22
RUN cp /bin/sleep /bin/sshd
ADD ./run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT /run.sh
