SD=/dev/sda
ROOTFS=rootfs.ext2
PAYLOAD=fw_payload.bin
ADD_DATA=out.bin


if sudo mount | grep -q ${SD}; then
    sudo umount ${SD}2
fi

sudo sgdisk --clear \
--new=1:2048:77783 \
--new=3:260096:262295 \
--new=2:264192:+300M \
--new=4 \
--typecode=1:3000 --typecode=2:8300 --typecode=3:8300 ${SD}
sudo partprobe
# ./server
sudo dd if=${PAYLOAD} of=${SD}1 bs=1M status=progress oflag=sync
sudo dd if=${ROOTFS} of=${SD}2 bs=1M status=progress oflag=sync 
sudo dd if=${ADD_DATA} of=${SD}3 bs=1M status=progress oflag=sync