#!/bin/bash

#PROGRAM="./tls_client ns1.esplab.io 12451 dil3"
PROGRAM="./tls_client ns1.esplab.io 12451"

#!/bin/bash

for i in {1..100}
do
   echo "Execution $i"
   $PROGRAM
   sleep 2
done
