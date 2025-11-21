#!/bin/bash
CURPATH=`pwd`
echo $CURPATH
ROOTPATH=$CURPATH
BUILDPATH=$ROOTPATH/target

[ -z ${SDE} ] && echo "Environment variable SDE not set" && exit 1
[ -z ${SDE_INSTALL} ] && echo "Environment variable SDE_INSTALL not set" && exit 1

export SDE=${SDE}
export SDE_INSTALL=${SDE_INSTALL}

if [ -d $BUILDPATH ]; then
   echo "删除旧目录重新编译"
   rm -rf $BUILDPATH
fi

mkdir -p $BUILDPATH

cd $BUILDPATH

cmake $SDE/p4studio/ -DTOFINO=OFF -DTOFINO2=ON \
   -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DCMAKE_MODULE_PATH=$SDE/cmake \
   -DP4_NAME=tofino2 -DP4_PATH=${ROOTPATH}/tofino2.p4

make tofino2

