#!/bin/bash
/bin/sshd 100 &
redis-server /etc/redis/redis.conf