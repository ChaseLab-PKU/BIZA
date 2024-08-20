# BIZA

*Design of Self-Governing Block-Interface ZNS AFA for Endurance and Performance!*

## Introduction

BIZA is a self-governing ZNS AFA that can benefit from the openness of ZNS interface whilst exposing the user-friendly block interface to upper-layer applications. 

We implement BIZA as a pluggable device mapper in Linux kernel (see `drivers/md/dm-biza*`). Expectedly, you can install it directly using `insmod` command. However, the support of ZRWA feature is still incomplete in the current kernel version. Therefore, we compromise to make some intrusive modifications to the block layer and NVMe driver, which complicates the installation process.

For fast deployment, we choose to release BIZA and Linux kernel as a whole. We've included all the necessary kernel codes for running BIZA in this repository. Therefore, you can deploy BIZA by simply compiling and installing this repository. 

This repository is developed on Linux kernel v5.15.0. We've also integrated [RAIZN](https://github.com/ZonedStorage/RAIZN-release) and [dm-zap](https://github.com/westerndigitalcorporation/dm-zap/tree/5.15_dm-zap) (with some improvement) in this repository for comparison. 

Please consider citing our paper at SOSP 2024 if you use BIZA. The BibTex is shown below: 

```latex
Coming soon...
```



## Environment

**Special Hardware:** Our tests require at least 4 WD ZN540 SSDs. BIZA would support other types of ZNS SSDs (but we have not validated this for the lack of hardware from other vendors). 

**Note:** Kernel modification is a **malicious and destructive** operation. Potential bugs may cause system crashes. Therefore, we **strongly** recommend you use BIZA on a virtual machine (VM). 

The following is an example to run VM with ZNS SSD:

```shell
OSIMG=path/to/your/os/img

sudo qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 32 \
    -m 128G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMG,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -device vfio-pci,host=0000:18:00.0,multifunction=on \
    -device vfio-pci,host=0000:19:00.0,multifunction=on \
    -device vfio-pci,host=0000:51:00.0,multifunction=on \
    -device vfio-pci,host=0000:52:00.0,multifunction=on \
    -net user,hostfwd=tcp::5555-:22 \
    -net nic,model=virtio \
    -nographic
```

Here, we use `vfio-pci` for PCIe passthrough. Related tutorials can be found [here](https://www.theseus-os.com/Theseus/book/running/virtual_machine/pci_passthrough.html).



## Setup

**Note:**  The current scripts are developed for Ubuntu 22.04 LTS. Porting to other OS may require some script modifications.

#### 1. Clone BIZA from Github:

```shell
mkdir biza && cd biza
mkdir build
git clone https://github.com/ChaseLab-PKU/BIZA.git
mv BIZA codes && cd codes
```

#### 2. Install the dependencies:

```shell
sudo apt update && sudo apt upgrade
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison libc6-dev liblz4-tool
```

#### 3. Compile  and Install BIZA:

In fact, you can compile and install BIZA with the same way as a common Linux kernel. Lots of guidances can be found online. For example:

```shell
make -j $(nproc) deb-pkg	# really time-consuming
cd ..
mv linux-* build/
cd build
sudo dpkg -i *.deb
```

Afterward, when you reboot your machine, you can choose the new kernel that contains BIZA.



## Run

When you've opened your server with the new kernel,  you can create BIZA target with bash command. Here is an example to create BIZA with 4 ZNS SSDs as RAID 5:

```shell
echo "0 409600 biza 4 1 64 /dev/nvme0n2 /dev/nvme1n2 /dev/nvme2n2 /dev/nvme3n2" | sudo dmsetup create biza0
# /dev/nvme*n2 are your ZNS SSDs.
```

If your DRAM capacity is not enough, please divide your ZNS SSD into smaller namespaces in advance,  see [here](https://nvmexpress.org/resource/nvme-namespaces/).

Afterward, you can find a new device named `/dev/dm-*`  with `lsblk` command. Just use it as a common block device!

