#!/bin/bash
# Run at the Mininet CLI prompt from the repository root.
set -e
h1 python3 app/tcp_client.py 10.0.0.5 5000 "normal traffic from h1"
h2 python3 app/tcp_client.py 10.0.0.5 5000 "normal traffic from h2"
h3 python3 app/tcp_client.py 10.0.0.5 5000 "normal traffic from h3"
