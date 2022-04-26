#!/bin/bash
length=$(($#-1))
OPTIONS=${@:1:$length}
REPONAME="${!#}"
CWD=$PWD
echo -e "\n\nInstalling commons libraries...\n\n"
COMMONS="so-commons-library"
git clone "https://github.com/sisoputnfrba/${COMMONS}.git" $COMMONS
cd $COMMONS
sudo make uninstall
make all
sudo make install
cd $CWD
echo -e "\n\nInstalling CUnit libraries...\n\n"
sudo apt-get install -y libcunit1 libcunit1-doc libcunit1-dev
echo -e "\n\nBuilding projects...\n\n"
make all
echo -e "\n\nDeploy done!\n\n"
