#!/bin/bash
START=$1
END=$2
TEMPLATE=template.json

for i in $(seq $START $END)
do
	P="pkg:maven/io.seedwing/seedwing-java-example@1.0.$i-SNAPSHOT?type=jar"
	cat $TEMPLATE | sed -e "s,SECRET_PURL,$P,g" > tmp.json
	echo "Publishing mysbom$i"
	curl -s -X PUT -d@tmp.json http://localhost:8080/api/v1/sbom/mysbom$i
	#curl -s -X PUT -d@tmp.json https://bombastic-api-bombastic.apps.sandbox.drogue.world/api/v1/sbom/mysbom$i
done
