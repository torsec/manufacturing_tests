#!/bin/bash
set -e

SD=/dev/mmcblk0

ROOTFS=rootfs.ext2
PAYLOAD=fw_payload.bin
ADD_DATA=out.bin

ADD_DATA_SIZE_BYTES=$(stat -c%s "$ADD_DATA")
PAYLOAD_SIZE_BYTES=$(stat -c%s "$PAYLOAD")
ROOTFS_SIZE_BYTES=$(stat -c%s "$ROOTFS")

ADD_DATA_SIZE_SECTORS=$(( (ADD_DATA_SIZE_BYTES + 511) / 512 ))
PAYLOAD_SIZE_SECTORS=$(( (PAYLOAD_SIZE_BYTES + 511) / 512 ))
ROOTFS_SIZE_SECTORS=$(( (ROOTFS_SIZE_BYTES + 511) / 512 ))

ALIGNMENT=2048

START_PAYLOAD_BLOCK=$ALIGNMENT
END_PAYLOAD_BLOCK=$((START_PAYLOAD_BLOCK + PAYLOAD_SIZE_SECTORS - 1))

START_ROOTFS_BLOCK=$(( (END_PAYLOAD_BLOCK + ALIGNMENT) / ALIGNMENT * ALIGNMENT ))
END_ROOTFS_BLOCK=$((START_ROOTFS_BLOCK + ROOTFS_SIZE_SECTORS - 1))

START_ADD_DATA_BLOCK=$(( (END_ROOTFS_BLOCK + ALIGNMENT) / ALIGNMENT * ALIGNMENT ))
END_ADD_DATA_BLOCK=$((START_ADD_DATA_BLOCK + ADD_DATA_SIZE_SECTORS - 1))

START_LAST_PARTITION_BLOCK=$(( (END_ADD_DATA_BLOCK + ALIGNMENT) / ALIGNMENT * ALIGNMENT ))

./crit.sh

for part in $(ls ${SD}* | grep -v ${SD}$); do
    if sudo mount | grep -q ${part}; then
        sudo umount ${part}
    fi
done

sudo sgdisk -g --clear \
--new=1:${START_PAYLOAD_BLOCK}:${END_PAYLOAD_BLOCK} \
--new=2:${START_ROOTFS_BLOCK}:${END_ROOTFS_BLOCK} \
--new=3:${START_ADD_DATA_BLOCK}:${END_ADD_DATA_BLOCK} \
--new=4:${START_LAST_PARTITION_BLOCK}: \
--typecode=1:3000 --typecode=2:8300 --typecode=3:8300 --typecode=4:8300 ${SD}

sudo partprobe
sleep 1

sudo fdisk -l ${SD}

counter=1

for part in $(ls ${SD}* | grep -v ${SD}$); do
    varname="PARTITION_${counter}"
    eval "${varname}=${part}"
    counter=$((counter + 1))
done


sudo dd if=${ADD_DATA} of=${PARTITION_3} bs=1M status=progress oflag=sync
sync
sudo dd if=${PAYLOAD} of=${PARTITION_1} bs=1M status=progress oflag=sync
sync
sudo dd if=${ROOTFS} of=${PARTITION_2} bs=1M status=progress oflag=sync
sync

ADD_DATA_CHECKSUM=$(md5sum ${ADD_DATA} | awk '{ print $1 }')
PAYLOAD_CHECKSUM=$(md5sum ${PAYLOAD} | awk '{ print $1 }')
ROOTFS_CHECKSUM=$(md5sum ${ROOTFS} | awk '{ print $1 }')

ADD_DATA_FLASHED_CHECKSUM=$(sudo dd if=${PARTITION_3} bs=1M count=${ADD_DATA_SIZE_BYTES} iflag=count_bytes status=none | md5sum | awk '{ print $1 }')
PAYLOAD_FLASHED_CHECKSUM=$(sudo dd if=${PARTITION_1} bs=1M count=${PAYLOAD_SIZE_BYTES} iflag=count_bytes status=none | md5sum | awk '{ print $1 }')
ROOTFS_FLASHED_CHECKSUM=$(sudo dd if=${PARTITION_2} bs=1M count=${ROOTFS_SIZE_BYTES} iflag=count_bytes status=none | md5sum | awk '{ print $1 }')
if [ "$ADD_DATA_CHECKSUM" == "$ADD_DATA_FLASHED_CHECKSUM" ]; then
    echo "ADD_DATA flashed correctly."
else
    echo "ADD_DATA flashing failed."
fi

if [ "$PAYLOAD_CHECKSUM" == "$PAYLOAD_FLASHED_CHECKSUM" ]; then
    echo "PAYLOAD flashed correctly."
else
    echo "PAYLOAD flashing failed."
fi

if [ "$ROOTFS_CHECKSUM" == "$ROOTFS_FLASHED_CHECKSUM" ]; then
    echo "ROOTFS flashed correctly."
else
    echo "ROOTFS flashing failed."
fi
