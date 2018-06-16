#! /bin/bash


cd # goto current users home directory



sudo apt-get update
sudo apt-get --yes --force-yes install git


# totally disable swap ---------------
sudo service dphys-swapfile stop
sudo systemctl disable dphys-swapfile
sudo apt-get --yes --force-yes purge dphys-swapfile
# totally disable swap ---------------

# ------------- install packages -------------
sudo apt-get --yes --force-yes install libjpeg-dev libpng-dev imagemagick htop mc fbset cmake qrencode
sudo apt-get --yes --force-yes install libqrencode-dev vim nano wget git make
sudo apt-get --yes --force-yes install autotools-dev libtool bc libv4l-dev libv4lconvert0 v4l-conf v4l-utils
sudo apt-get --yes --force-yes install libopus-dev libvpx-dev pkg-config libjpeg-dev libpulse-dev libconfig-dev
sudo apt-get --yes --force-yes install automake checkinstall check yasm
sudo apt-get --yes --force-yes install libao-dev libasound2-dev speedometer

sudo apt-get --yes --force-yes install imagemagick qrencode tor tor-arm
# ------------- install packages -------------



export CF2=" -O3 -g -marm -march=armv8-a+crc -mtune=cortex-a53 -mfpu=neon-fp-armv8 -mfloat-abi=hard -ftree-vectorize "
export CF3=" -funsafe-math-optimizations "
export VV1=" VERBOSE=1 V=1 "

## ---- settings ----
## ---- settings ----
export FULL=1
export FASTER=0
## ---- settings ----
## ---- settings ----


export ASAN=0

export _HOME_=$(pwd)
echo $_HOME_


if [ "$FULL""x" == "1x" ]; then
    # check out TBW aswell
    cd $_HOME_
    git clone https://github.com/zoff99/ToxBlinkenwall
fi

cd $_HOME_/ToxBlinkenwall/toxblinkenwall/

./initscript.sh stop

cat /dev/zero > /dev/fb0
sleep 1

export _SRC_=$_HOME_/src/
export _INST_=$_HOME_/inst/

mkdir -p $_SRC_
mkdir -p $_INST_

export LD_LIBRARY_PATH=$_INST_/lib/
export PKG_CONFIG_PATH=$_INST_/lib/pkgconfig







if [ "$FULL""x" == "1x" ]; then



cd $_SRC_
# rm -Rf libav
git clone https://github.com/libav/libav
cd libav
git checkout v12.3
./configure --prefix=$_INST_ --disable-devices --disable-programs \
--disable-doc --disable-avdevice --disable-avformat \
--disable-swscale \
--disable-avfilter --disable-network --disable-everything \
--disable-bzlib \
--disable-libxcb-shm \
--disable-libxcb-xfixes \
--enable-parser=h264 \
--enable-runtime-cpudetect \
--enable-omx-rpi --enable-mmal \
--enable-omx \
--enable-decoder=h264_mmal \
--enable-decoder=h264_vdpau \
--enable-vdpau \
--enable-gpl --enable-decoder=h264
make clean
make -j4
make install




cd $_SRC_
# rm -Rf x264
git clone git://git.videolan.org/x264.git
cd x264
git checkout stable
./configure --prefix=$_INST_ --disable-opencl --enable-shared --enable-static \
--disable-avs --disable-cli
make clean
make -j4
make install



cd $_SRC_
git clone --depth=1 --branch=1.0.13 https://github.com/jedisct1/libsodium.git
cd libsodium
make clean
./autogen.sh
export CFLAGS=" $CF2 "
./configure --prefix=$_INST_ --disable-shared --disable-soname-versions # --enable-minimal
make -j 4
make install


cd $_SRC_
git clone --depth=1 --branch=v1.7.0 https://github.com/webmproject/libvpx.git
cd libvpx
make clean
export CFLAGS=" $CF2 $CF3 "
export CXXLAGS=" $CF2 $CF3 "
./configure --prefix=$_INST_ --disable-examples \
  --disable-unit-tests --enable-shared \
  --size-limit=16384x16384 \
  --enable-onthefly-bitpacking \
  --enable-error-concealment \
  --enable-runtime-cpu-detect \
  --enable-multi-res-encoding \
  --enable-postproc \
  --enable-vp9-postproc \
  --enable-temporal-denoising \
  --enable-vp9-temporal-denoising

#  --enable-better-hw-compatibility \

make -j 4
make install


cd $_SRC_
git clone --depth=1 --branch=v1.2.1 https://github.com/xiph/opus.git
cd opus
make clean
./autogen.sh
export CFLAGS=" $CF2 $CF3 "
export CXXLAGS=" $CF2 $CF3 "
./configure --prefix=$_INST_ --disable-shared
make -j 4
make install

fi



cd $_SRC_

if [ "$FULL""x" == "1x" ]; then
    git clone https://github.com/zoff99/c-toxcore_team c-toxcore
    cd c-toxcore
    git checkout zoff99/toxcore_v1.0.10__toxav_h264_001
    ## ** ## git pull
else
    cd c-toxcore
fi


export CFLAGS=" $CF2 -D_GNU_SOURCE -I$_INST_/include/ -O3 -g -fstack-protector-all "
export LDFLAGS=-L$_INST_/lib

if [ "$FASTER""x" == "0x" ]; then
    ./autogen.sh

    ./configure \
    --prefix=$_INST_ \
    --disable-soname-versions --disable-testing --disable-shared --enable-raspi
    make clean
fi

make -j 4 && make install
res=$?


if [ $res -eq 0 ]; then

cd $_HOME_/ToxBlinkenwall/toxblinkenwall/

_OO_=" -g "

if [ "$ASAN""x" == "1x" ]; then
	CF2="$CF2 -fsanitize=address"
	LL1="" # "-lasan" # "-static-libasan"
	_OO_=" -g "
fi

gcc $_OO_ \
-DRASPBERRY_PI -DOMX_SKIP64BIT -DUSE_VCHIQ_ARM \
-I/opt/vc/include -I/opt/vc/interface/vmcs_host/linux -I/opt/vc/interface/vcos/pthreads \
$CF2 $CF3 \
$LL1 \
-fstack-protector-all \
-Wno-unused-variable \
-fPIC -export-dynamic -I$_INST_/include -o toxblinkenwall -lm \
toxblinkenwall.c openGL/esUtil.c openGL/esShader.c rb.c \
-I/opt/vc/include -I/opt/vc/include/interface/vcos/pthreads \
-I/opt/vc/include/interface/vmcs_host/linux -lbrcmEGL -lbrcmGLESv2 \
-lbcm_host -L/opt/vc/lib \
-std=gnu99 \
-L$_INST_/lib \
$_INST_/lib/libtoxcore.a \
$_INST_/lib/libtoxav.a \
-lrt \
$_INST_/lib/libopus.a \
$_INST_/lib/libvpx.a \
$_INST_/lib/libx264.a \
$_INST_/lib/libavcodec.a \
$_INST_/lib/libavutil.a \
$_INST_/lib/libsodium.a \
-lasound \
-lpthread -lv4lconvert \
-lmmal -lmmal_core -lmmal_vc_client -lmmal_components -lmmal_util \
-L/opt/vc/lib -lbcm_host -lvcos -lopenmaxil

res2=$?

cd $_HOME_

	if [ $res2 -eq 0 ]; then
		$_HOME_/ToxBlinkenwall/toxblinkenwall/initscript.sh start
	else
		echo "ERROR !!"
		# cat /dev/urandom > /dev/fb0
		$_HOME_/fill_fb.sh "1 1 1 1 1"
	fi

else
	echo "ERROR !!"
	cat /dev/urandom > /dev/fb0
fi


rm -f $_HOME_/compile_me.txt

