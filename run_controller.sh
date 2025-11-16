#!/bin/bash
source /root/miniconda3/etc/profile.d/conda.sh
conda activate controller

CURPATH=$(cd `dirname $0`; pwd)

cd $SDE
./run_p4_tests.sh -t $CURPATH/ --setup
cd $CURPATH

# conda deactivate