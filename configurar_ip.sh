#!/bin/bash
ip=$2
case $1 in

  memoria)
    proc_name=MEMORIA
    ;;

  kernel)
    proc_name=KERNEL
    ;;

  cpu)
    proc_name=CPU
    ;;

  *)
    echo -n "	Uso: ./configurar_ip.sh [memoria|cpu|kernel] 127.0.0.1


"
    exit -1
    ;;
esac
find . -name '*.config' -exec sed -i -e "s/IP_${proc_name}=127.0.0.1/IP_${proc_name}=$ip/g" {} \;
#echo "s/IP_$proc_name=127.0.0.1/IP_MEMORIA=$ip/g";
