#!/bin/bash

PROGRAM="./tls_client ns1.esplab.io 12450 sph192f"

#PROGRAM="./pas_client ns1.esplab.io 12451 sph192f"
#PROGRAM="./act_client ns1.esplab.io 12451 sph192f"

# tcp_rmem 설정 값 배열
sizes=(131072 262144)

# 각 크기에 대해 실행
for size in "${sizes[@]}"
do
    # sysctl을 사용하여 tcp_rmem 설정 변경
    echo "Setting tcp_rmem to $size $size $size"
    sudo sysctl -w net.ipv4.tcp_rmem="$size $size $size"

    # tls_client 프로그램을 30번 실행
    for i in {1..20}
    do
        echo "Execution $i with tcp_rmem size $size"
        $PROGRAM
        sleep 1
    done
done

echo "Test sequence completed."

