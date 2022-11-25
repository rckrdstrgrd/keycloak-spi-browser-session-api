#!/bin/bash
docker run --rm -v $PWD:/usr/src maven:3-openjdk-18 sh -c "cd /usr/src && mvn -T 1C -q clean package"
