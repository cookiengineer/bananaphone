#!/bin/sh
# assume we have image dir mounted to /image and image/boot.img present
EARLYBOOT_FILE=init.qcom.early_boot.sh
cd /image
cp boot.img boot-orig.img
echo 'Boot image found, patching...'
abootimg -x boot.img
mkdir initrd
cd initrd
cat ../initrd.img | gunzip | cpio -vid
# initrd root patch process start
cp /home/8k/adbd ./sbin/
cp /home/8k/slua ./sbin/
cp /home/8k/sluac ./sbin/
sed -i 's/ro\.secure.*/ro.secure=0/' ./default.prop
sed -i 's/ro\.debuggable.*/ro.debuggable=1/' ./default.prop
sed -i 's/.*perf_harden.*/security.perf_harden=0/' ./default.prop
sed -i '/.*reload_policy.*/d' ./init.rc
echo 'setenforce 0' >> ./$EARLYBOOT_FILE
echo 'echo -n 1 > /data/enforce' >> ./$EARLYBOOT_FILE
echo 'mount -o bind /data/enforce /sys/fs/selinux/enforce' >> ./$EARLYBOOT_FILE
# initrd root patch process end
find . | cpio --create --format='newc' | gzip > ../myinitrd.img
cd ..
# bootimg.cfg patch process start
sed -i 's/^cmdline.*/& androidboot.selinux=permissive enforcing=0/' bootimg.cfg
# bootimg.cfg patch process end
abootimg -u boot.img -f bootimg.cfg -r myinitrd.img
rm -rf *initrd* bootimg.cfg zImage
echo 'Boot image patched!'
# ...Nothing can stop an idea whose time has come
