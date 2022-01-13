programs="mosquitto_sub tshark h1p.sh h2p.sh h3p.sh h4p.sh h1b.sh h2b.sh h3b.sh h4b.sh"

for program in programs; do
  pids=`pgrep ${program}`
  for pid in $pids; do
    sudo kill -9 $pid
  done
done

