#!/bin/bash

npm run build

rm -rf ../static/*
#rm -rf ../templates/html/*

cp -r build/* ../static/

#for file in $(find build -name *.html); do
#  cp "$file" ../templates/html/
#done