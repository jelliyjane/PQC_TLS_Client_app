for i in {1..55}
do
	./pas_client esplab.io 12451 dil2
	echo "express dil2 $i"
	sleep 2
done

for i in {1..55}
do
	./pas_tls_client esplab.io 12451 dil2
	echo "tls dil2 $i"
	sleep 2
done

for i in {1..55}
do
	./pas_client esplab.io 12451 dil3
	echo "express dil3 $i"
	sleep 2
done

for i in {1..55}
do
	./pas_tls_client esplab.io 12451 dil3
	echo "tls dil3 $i"
	sleep 2
done

for i in {1..65}
do
	./pas_client esplab.io 12451 dil5
	echo "express dil5 $i"
	sleep 2
done

for i in {1..55}
do
	./pas_tls_client esplab.io 12451 dil5
	echo "tls dil5 $i"
	sleep 2
done

for i in {1..55}
do
	./pas_client esplab.io 12451 fal512
	echo "express fal512 $i"
	sleep 2
done

for i in {1..50}
do
	./pas_client esplab.io 12451 fal512
	echo "tls fal512 $i"
	sleep 2
done

for i in {1..55}
do
	./pas_client esplab.io 12451 fal1024
	echo "express fal1024 $i"
	sleep 2
done

for i in {1..50}
do
	./pas_client esplab.io 12451 fal1024
	echo "tls fal1024 $i"
	sleep 2
done