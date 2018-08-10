#! /bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_


echo $_HOME_
cd $_HOME_
mkdir -p build

export _SRC_=$_HOME_/build/
export _INST_=$_HOME_/inst/

echo $_SRC_
echo $_INST_

mkdir -p $_SRC_
mkdir -p $_INST_

export PKG_CONFIG_PATH=$_INST_/lib/pkgconfig



full="1"

if [ "$full""x" == "1x" ]; then

cd $_HOME_/build
rm -Rf libav
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
--enable-gpl --enable-decoder=h264
make -j4
make install


cd $_HOME_/build
rm -Rf x264
git clone git://git.videolan.org/x264.git
cd x264
git checkout stable
./configure --prefix=$_INST_ --disable-opencl --enable-shared --enable-static \
--disable-avs --disable-cli
make -j4
make install



# cd $_HOME_/build
# rm -Rf nasm
# git clone http://repo.or.cz/nasm.git
# cd nasm
# git checkout nasm-2.13.03
# ./autogen.sh
# ./configure --prefix=$_INST_
# make -j4
# # seems man pages are not always built. but who needs those
# touch nasm.1
# touch ndisasm.1
# make install


# cd $_HOME_/build
# rm -Rf openh264
# git clone https://github.com/cisco/openh264
# cd openh264
# git checkout v1.7.0
# export PA_COPY=$PATH
# export PATH=$_INST_/bin:$PATH
# sed -i -e 's#PREFIX=.*#PREFIX='$_INST_'#' Makefile
# make ARCH=x86_64 PREFIX=$_INST_
# make install
# export PATH=$PA_COPY


cd $_HOME_/build
rm -Rf libsodium
git clone https://github.com/jedisct1/libsodium
cd libsodium
git checkout 1.0.13
autoreconf -fi
./configure --prefix=$_INST_ --disable-shared --disable-soname-versions
make -j4
make install


cd $_HOME_/build
rm -Rf opus
git clone https://github.com/xiph/opus.git
cd opus
git checkout v1.2.1
./autogen.sh
./configure --prefix=$_INST_ --disable-shared
make -j 4
make install


cd $_HOME_/build
rm -Rf libvpx
git clone https://github.com/webmproject/libvpx.git
cd libvpx
git checkout v1.7.0
export CFLAGS=" -g -O3 -I$_INST_/include/ -Wall -Wextra "
export LDFLAGS=" -O3 -L$_INST_/lib "
./configure --prefix=$_INST_ --disable-examples \
  --disable-unit-tests --enable-shared \
  --size-limit=16384x16384 \
  --enable-postproc --enable-multi-res-encoding \
  --enable-temporal-denoising --enable-vp9-temporal-denoising \
  --enable-vp9-postproc
make -j 4
make install
unset CFLAGS
unset LDFLAGS


cd $_HOME_/build
rm -Rf filter_audio
git clone https://github.com/irungentoo/filter_audio.git
cd filter_audio
export DESTDIR=$_INST_
export PREFIX=""
make
make install
export DESTDIR=""
unset DESTDIR
export PREFIX=""
unset PREFIX


fi




cd $_HOME_/build


if [ "$full""x" == "1x" ]; then
    rm -Rf c-toxcore
    git clone https://github.com/zoff99/c-toxcore_team
    cd c-toxcore
    git checkout zoff99/zoff99/toxcore_v1.0.10__toxav_h264_001
    ./autogen.sh
    export CFLAGS=" -D_GNU_SOURCE-g -O3 -I$_INST_/include/ "
    export LDFLAGS=" -O3 -L$_INST_/lib "
    ./configure \
      --prefix=$_INST_ \
      --disable-soname-versions --disable-testing --disable-shared
    unset CFLAGS
    unset LDFLAGS
else
    rsync -av /home/zoff/toxc2/c-toxcore/ ./c-toxcore/
    cd c-toxcore
    # git pull

    make clean
    #./autogen.sh

    export CFLAGS=" -D_GNU_SOURCE -g -O0 -I$_INST_/include/ -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable "
    export LDFLAGS=" -O0 -L$_INST_/lib "
    ./configure \
      --prefix=$_INST_ \
      --disable-soname-versions --disable-testing --enable-logging --disable-shared
    # --disable-testing
    unset CFLAGS
    unset LDFLAGS

fi

make -j 4 || exit 1
make test



make install
# libtool --finish $_INST_/lib


# cd $_HOME_
# gcc -O0 -g -Iinst/include/ -Linst/lib/ -o a a.c \
# -ltoxcore -ltoxav \
# -lopus \
# -lvpx \
# -lpthread \
# -lsodium





