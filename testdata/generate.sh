#!/bin/bash
NUM=$1
TEMPLATE=template.json

for i in $(seq 1 $NUM)
do
	P="pkg:maven/io.seedwing/seedwing-java-example@1.0.$i-SNAPSHOT?type=jar"
	cat $TEMPLATE | sed -e "s,SECRET_PURL,$P,g" > tmp.json
	curl -X PUT -d@tmp.json http://localhost:8080/api/v1/sbom/mysbom$i
done
