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
./configure --prefix=$_INST_ \
  --disable-examples \
  --disable-unit-tests \
  --enable-shared \
  --size-limit=16384x16384 \
  --enable-onthefly-bitpacking \
  --enable-runtime-cpu-detect \
  --enable-multi-res-encoding \
  --enable-error-concealment \
  --enable-better-hw-compatibility \
  --enable-postproc \
  --enable-vp9-postproc
  --enable-temporal-denoising \
  --enable-vp9-temporal-denoising
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
    git clone https://github.com/zoff99/c-toxcore_team c-toxcore
    cd c-toxcore
    git checkout zoff99/toxcore_v1.0.10__toxav_h264_001 ## new branch now!!
    ./autogen.sh
    export CFLAGS=" -g -O0 -I$_INST_/include/ "
    export LDFLAGS=" -O0 -L$_INST_/lib "
    ./configure \
      --prefix=$_INST_ \
      --disable-soname-versions --disable-testing --disable-shared
    unset CFLAGS
    unset LDFLAGS
else
    rsync -av /home/zoff/toxc2/c-toxcore/ ./c-toxcore/
    cd c-toxcore
    # git pull

    # ./autogen.sh
    make clean

    export CFLAGS=" -D_GNU_SOURCE -g -O0 -I$_INST_/include/ -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable "
    export LDFLAGS=" -O3 -L$_INST_/lib "
    ./configure \
      --prefix=$_INST_ \
      --disable-soname-versions --disable-testing --enable-logging --disable-shared
    # --disable-testing
    unset CFLAGS
    unset LDFLAGS

fi

make -j 4 || exit 1




make install
# libtool --finish $_INST_/lib


cd $_HOME_/build

mkdir -p utox_build
cd utox_build/



## rsync -av $_HOME_/uTox/ ./

# --recurse-submodules

git clone https://github.com/zoff99/uTox ./
git checkout zoff99/linux_custom_003

git submodule update --init --recursive

mkdir build2
cd build2/


O_OPTIONS=" -O0 "

export PKG_CONFIG_PATH=$_INST_/lib/pkgconfig
export CFLAGS=" -g $O_OPTIONS -I$_INST_/include/ -L$_INST_/lib -Wl,-Bstatic -lsodium -ltoxav -lopus -lvpx -lm -ltoxcore -ltoxdns -ltoxencryptsave -Wl,-Bdynamic "

cmake \
 -DENABLE_AUTOUPDATE=OFF \
 -DENABLE_DBUS=OFF \
 -DASAN=OFF \
 -DENABLE_ASAN=OFF \
 -DTOXCORE_STATIC=ON \
 -DUTOX_STATIC=ON \
 ../

make clean > /dev/null 2> /dev/null

# make VERBOSE=1 V=1 -j 8
make -j 8

unset CFLAGS
# unset PKG_CONFIG_PATH

rm -f utox

cc  -g $O_OPTIONS -I$_INST_/include/   \
-L$_INST_/lib \
-Wall -Wextra -Wpointer-arith -Werror=implicit-function-declaration \
-Wformat=0 -Wno-misleading-indentation -fno-strict-aliasing -fPIC -flto  \
-Wl,-z,noexecstack CMakeFiles/utox.dir/src/avatar.c.o \
CMakeFiles/utox.dir/src/chatlog.c.o CMakeFiles/utox.dir/src/chrono.c.o \
CMakeFiles/utox.dir/src/command_funcs.c.o CMakeFiles/utox.dir/src/commands.c.o \
CMakeFiles/utox.dir/src/devices.c.o CMakeFiles/utox.dir/src/file_transfers.c.o \
CMakeFiles/utox.dir/src/filesys.c.o CMakeFiles/utox.dir/src/flist.c.o \
CMakeFiles/utox.dir/src/friend.c.o CMakeFiles/utox.dir/src/groups.c.o \
CMakeFiles/utox.dir/src/inline_video.c.o CMakeFiles/utox.dir/src/logging.c.o \
CMakeFiles/utox.dir/src/main.c.o CMakeFiles/utox.dir/src/messages.c.o \
CMakeFiles/utox.dir/src/notify.c.o CMakeFiles/utox.dir/src/screen_grab.c.o \
CMakeFiles/utox.dir/src/self.c.o CMakeFiles/utox.dir/src/settings.c.o \
CMakeFiles/utox.dir/src/stb.c.o CMakeFiles/utox.dir/src/text.c.o \
CMakeFiles/utox.dir/src/theme.c.o CMakeFiles/utox.dir/src/tox.c.o \
CMakeFiles/utox.dir/src/tox_callbacks.c.o CMakeFiles/utox.dir/src/ui.c.o \
CMakeFiles/utox.dir/src/ui_i18n.c.o CMakeFiles/utox.dir/src/updater.c.o \
CMakeFiles/utox.dir/src/utox.c.o CMakeFiles/utox.dir/src/window.c.o  \
-o utox \
-rdynamic src/av/libutoxAV.a \
src/xlib/libutoxNATIVE.a src/ui/libutoxUI.a \
-lrt -lpthread -lm -lopenal \
src/xlib/libicon.a -lv4lconvert \
-lSM -lICE -lX11 -lXext -lXrender \
-lfontconfig -lfreetype -lresolv -ldl \
-Wl,-Bstatic $_INST_/lib/libopus.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libvpx.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libsodium.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libtoxcore.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libtoxav.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libtoxencryptsave.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libtoxdns.a -Wl,-Bdynamic \
-Wl,-Bstatic $_INST_/lib/libfilteraudio.a -Wl,-Bdynamic \
$_INST_/lib/libsodium.a \
$_INST_/lib/libopus.a \
$_INST_/lib/libvpx.a \
$_INST_/lib/libx264.a \
$_INST_/lib/libavcodec.a \
$_INST_/lib/libavutil.a \
CMakeFiles/utox.dir/third-party/qrcodegen/c/qrcodegen.c.o \
CMakeFiles/utox.dir/src/qr.c.o \
CMakeFiles/utox.dir/third-party/minini/dev/minIni.c.o \
src/layout/libutoxLAYOUT.a

# ldd utox

echo ""
echo ""
echo "########################"
echo "########################"

pwd
ls -hal utox
ls -al utox

