#!/usr/bin/env sh

device=""
redisIP=""
redisPort=""
timeout="0"
outputFile=""
onlyBigReq=""
onlyBigVal=""
upgrade=""

usage() {
	echo -e "Usage: $0 [OPTIONS]"
	echo -e "Use libpcap to capture redis request packet and decode packet."
	echo -e ""
	echo -e "--help -h display help info"
	echo -e "--device -d,network device. default eth1"
	echo -e "--ip -i,redis (dst) ip.default the ip corresponding to eth1"
	echo -e "--port -p,dst redis port. default the first 50* port in the /data/twemproxy directory"
	echo -e "--timeout -t,duration of capture in seconds.default 0 (no limit)"
	echo -e "--output-file -f,store output into file path.. default stdout"
	echo -e "--only-big-req. default 0 means no limit.Only output requests that process multibulklen > {--only-big-req}, such as mset or mget or pipeline"
	echo -e "--only-big-val. default 0 means no limit.only output write requests with a large value"
	echo -e "--upgrade. refetch latest myRedisCapture binary."
	exit 1
}

for i in "$@"; do
	case $i in
	-d=* | --device=*)
		device="${i#*=}"
		shift
		;;
	-i=* | --ip=*)
		redisIP="${i#*=}"
		shift
		;;
	-p=* | --port=*)
		redisPort="${i#*=}"
		shift
		;;
	-t=* | --timeout=*)
		timeout="${i#*=}"
		shift
		;;
	-f=* | --output-file=*)
		outputFile="${i#*=}"
		shift
		;;
	--only-big-req=*)
		onlyBigReq="${i#*=}"
		shift
		;;
	--only-big-val=*)
		onlyBigVal="${i#*=}"
		shift
		;;
	--upgrade)
		upgrade="1"
		;;
	-h | --help)
		usage
		;;
	*)
		echo -e "unknown option:$i"
		usage
		;;
	esac
done

#set default
if [[ -z $device ]]; then
	device="eth1"
fi

if [[ -z $redisIP ]]; then
	redisIP=$(ifconfig | grep -A 1 "eth" | grep "inet addr" | awk '{print $2}' | awk -F : '{print $2}')
	if [[ -z $redisIP ]]; then
		redisIP=$(ifconfig | grep -A 1 "eth" | grep "inet" | awk '{print $2}')
	fi
	if [[ -z $redisIP ]]; then
		echo -e "[ERROR] get the IP corresponding to eth1 fail"
		exit -1
	fi
fi

if [[ -z $redisPort ]]; then
	redisPort=$(ls /data/twemproxy* | grep -P "^50" | head -1)
	if [[ -z $redisPort ]]; then
		echo -e "[ERROR] get the first 50* port in the /data/twemproxy directory fail"
		exit -1
	fi
fi

device="--device=$device"
redisIP="--ip=$redisIP"
redisPort="--port=$redisPort"
timeout="--timeout=$timeout"

if [[ -n $outputFile ]]; then
	outputFile="--output-file=$outputFile"
fi

if [[ -n $onlyBigReq ]]; then
	onlyBigReq="--only-big-req=$onlyBigReq"
fi

if [[ -n $onlyBigVal ]]; then
	onlyBigVal="--only-big-val=$onlyBigVal"
fi

# cd /data/dbbak/

if [[ -n $upgrade && -e "./myRedisCapture" ]]; then
	rm -rf "./myRedisCapture"
fi

if [[ ! -e "./myRedisCapture" ]]; then
	wget http://9.225.16.188/data/gcslog/1122/myRedisCapture
fi
chmod a+x myRedisCapture

if [[ ! -e "./myRedisCapture" ]]; then
	echo -e "[ERROR] /data/dbbak/myRedisCapture fetch binary fail"
	exit -1
fi

echo -e "./myRedisCapture $device $redisIP $redisPort $timeout $outputFile $onlyBigReq $onlyBigVal"
./myRedisCapture $device $redisIP $redisPort $timeout $outputFile $onlyBigReq $onlyBigVal
