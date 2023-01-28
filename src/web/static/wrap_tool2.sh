#!/bin/sh

set -e

echo "\"use strict\";(function(g){var belenios={};"
#sed "s/(function(){return this}())/(g)/g" "$1"
cat $1 | sed "s/(function(){return this}())/(g)/g" | sed 's/require("fs")/{}/g' | sed 's/require("constants")/{}/g'
echo
echo "}(this));"
