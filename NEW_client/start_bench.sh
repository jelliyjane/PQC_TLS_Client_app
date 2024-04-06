#!/bin/bash

PROGRAM="./new_client ns1.esplab.io 12451 ns1.dil2.0.esplab.io ns1.dil2.1.esplab.io ns1.dil2.2.esplab.io ns1.dil2.3.esplab.io ns1.dil2.4.esplab.io ns1.dil2.5.esplab.io ns1.dil2.6.esplab.io "

#!/bin/bash

for i in {1..300}
do
   echo "Execution $i"
   $PROGRAM
   sleep 5
done
