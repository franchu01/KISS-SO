#!/bin/bash
echo -e "\n\nCleaning projects...\n\n"
make clean -C ./cpu
make clean -C ./memoria
make clean -C ./kernel
make clean -C ./consola

rm -r **/obj

