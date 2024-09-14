#!/bin/bash
dir=`pwd`
rm -rf ../src/*.skel.h
ln -s ${dir}/*.skel.h ../src
