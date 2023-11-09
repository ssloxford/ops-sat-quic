#!/bin/bash
USER=exp267
NAME=NedStevenson
version=$(git describe --tags)
if [[ $(git diff --stat) != '' ]]; then
 version="${version}-dirty"
else
 version="${version}-clean"
fi
package_name="$USER"_"$version"_"$NAME".zip
zip -r delivery/$package_name home/*
echo "Finished preparing ZIP file"
ls -lart delivery/$package_name