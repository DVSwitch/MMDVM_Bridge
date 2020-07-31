These are the binaries for MMDVM_Bridge. These binaries should be the latest version of MMDVM_Bridge. We place the binaries here so people can replace existing binaries if there is a hot fix before the program is upgraded in the apt repository. We build the binaries for the following architectures:

amd64 --- 64 bit Intel/AMD --- 3.16.0-4-amd64 #1 x86_64

arm64 --- 64 bit ARM --- 5.4.51-v8+ aarch64

armhf --- RPi2/3 --- 4.9.35-v7+ armv7l

armv6l --- RPi 1/Zero --- 4.9.35+ armv6l

i386 --- 32bit Intel/AMD --- 4.9.0-11-686-pae i686

The key information you will see when you type "uname -m" Also, see the output of "dpkg --print-architecture"
Once you have the binary downloaded to your host, you can rename the file to simply MMDVM_Bridge and replace the existing binary.
