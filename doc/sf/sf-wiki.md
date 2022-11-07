The goals of the kernel integrity subsystem are to detect if files have been accidentally or maliciously altered, both remotely and locally, appraise a file's measurement against a "good" value stored as an extended attribute, and enforce local file integrity. These goals are complementary to Mandatory Access Control(MAC) protections provided by LSM modules, such as SElinux and Smack, which, depending on policy, can attempt to protect file integrity.

[TOC]

## Overview
### Features

The following modules provide several integrity functions:

-   **Collect** – measure a file before it is accessed.
-   **Store** – add the measurement to a kernel resident list and, if a
    hardware Trusted Platform Module (TPM) is present, extend the IMA
    PCR
-   **Attest** – if present, use the TPM to sign the IMA PCR value, to
    allow a remote validation of the measurement list.
-   **Appraise** – enforce local validation of a measurement against a
    “good” value stored in an extended attribute of the file.
-   **Protect** – protect a file's security extended attributes
    (including appraisal hash) against off-line attack.

 -   **Audit** – audit the file hashes.

The first three functions were introduced with Integrity Measurement Architecture ([IMA](#integrity-measurement-architecture-ima)) in 2.6.30.   The "appraise" and "protect" features were originally posted as a single [EVM](#linux-extended-verification-module-evm)/[IMA-appraisal](#ima-appraisal) patch set for in the 2.6.36 timeframe, but were subsequently split.   EVM, the "protect" feature, was upstreamed in Linux 3.2, using a simplier and more secure method for loading the 'evm-key', based on the new Kernel Key Retention [Trusted and Encrypted keys](#creating-trusted-and-evm-encrypted-keys).   EVM support for protecting file metadata based on digital signatures was upstreamed in the Linux 3.3.  IMA-appraisal, the fourth aspect, appraising a file's integrity, was upstreamed in Linux 3.7.

The goals, design, and benefits of these features are further described in the whitepaper ["An Overview of the Linux Integrity Subsystem"](http://downloads.sf.net/project/linux-ima/linux-ima/Integrity_overview.pdf "http://downloads.sf.net/project/linux-ima/linux-ima/Integrity_overview.pdf").

### Components

IMA-measurement, one component of the kernel's integrity subsystem, is part of an overall Integrity Architecture based on the Trusted Computing Group's open standards, including Trusted Platform Module (TPM), Trusted Boot, Trusted Software Stack (TSS), Trusted Network Connect (TNC), and Platform Trust Services (PTS). The linux-ima project page contains a [diagram](http://linux-ima.sourceforge.net/) showing how these standards relate, and provides links to the respective specifications and open source implementations. IMA-measurement and EVM can still run on platforms without a hardware TPM, although without the hardware guarantee of compromise detection.

IMA-appraisal, a second component of the kernel's integrity subsystem,  extends the "secure boot" concept of verifying  a file's integrity, before transferring control or allowing the file to be accessed by the OS.

IMA-audit, another component of the kernel's integrity subsystem, includes file hashes in the system audit logs, which can be used to augment existing system security analytics/forensics.

The IMA-measurement, IMA-appraisal, and IMA-audit aspects of the kernel's integrity subsystem complement each other, but can be configured and used independently of each other.

## Integrity Measurement Architecture (IMA-measurement)


IMA-measurement is an open source trusted computing component. IMA maintains a runtime measurement list and, if anchored in a hardware Trusted Platform Module(TPM), an aggregate integrity value over this list. The benefit of anchoring the aggregate integrity value in the TPM is that the measurement list cannot be compromised by any software attack, without being detectable. Hence, on a trusted boot system, IMA-measurement can be used to attest to the system's runtime integrity.

### Enabling IMA-measurement

IMA was first included in the 2.6.30 kernel. For distros that enable IMA by default in their kernels, collecting IMA measurements simply requires rebooting the kernel with a builtin  "ima_policy=" on the boot command line. (Fedora/RHEL may also require the boot command line parameter 'ima=on'.)

To determine if your distro enables IMA by default, mount securityfs (mount -t securityfs security /sys/kernel/security), if it isn't already mounted, and then check if '<securityfs>/integrity/ima' exists. If it exists, IMA is indeed enabled. On systems without IMA enabled, [recompile the kernel](#compiling-the-kernel-with-evmima-appraisal-enabled) with the config option 'CONFIG_IMA' enabled.

### Controlling IMA-measurement

IMA is controlled with several kernel command line parameters:


ima_audit= informational audit logging
 Format: { "0" | "1" }
 0 -- normal integrity auditing messages. (Default)
 1 -- enable additional informational integrity auditing messages.

 (eg. Although file measurements are only added to the measurement list once and cached, if the inode is flushed, subsequent access to the inode will result in re-measuring the file and attempting to add the measurement again to the measurement list. Enabling ima_audit will log such attempts.)

ima_policy= builtin policy
Format:  {"tcb" | "appraise_tcb" | "secure-boot"}
**NEW** Linux-4.13 default: no policy

ima_template= template used
 Format: { "ima" | "ima-ng" | "ima-sig" }
 Linux 3.13 default: "ima-ng"

ima_hash= hash used
 Format: { "sha1" | "md5" | "sha256" | "sha512" | "wp512" | ... }
  'ima' template default: "sha1"
  Linux 3.13 default: "sha256"

 ima_tcb  (deprecated)
 If specified, enables the TCB policy, which meets the needs of the Trusted Computing Base. This means IMA will measure all programs exec'd, files mmap'd for exec, and all files opened for read by uid=0.

### IMA Measurement List

IMA-measurements maintains a runtime measurement list, which can be displayed as shown below.

- mount securityfs as /sys/kernel/security

    $ su -c 'mkdir /sys/kernel/security'
    $ su -c 'mount -t securityfs securityfs /sys/kernel/security'

Modify /etc/fstab to mount securityfs on boot.

- display the runtime measurement list    (Only root is allowed access to securityfs files.)

Example 1: 'ima-ng' template
    $ su -c 'head -5 /sys/kernel/security/ima/ascii_runtime_measurements'

    PCR     template-hash                           filedata-hash                           filename-hint
    10 91f34b5c671d73504b274a919661cf80dab1e127 ima-ng sha1:1801e1be3e65ef1eaa5c16617bec8f1274eaf6b3 boot_aggregate
    10 8b1683287f61f96e5448f40bdef6df32be86486a ima-ng sha256:efdd249edec97caf9328a4a01baa99b7d660d1afc2e118b69137081c9b689954 /init
    10 ed893b1a0bc54ea5cd57014ca0a0f087ce71e4af ima-ng sha256:1fd312aa6e6417a4d8dcdb2693693c81892b3db1a6a449dec8e64e4736a6a524 /usr/lib64/ld-2.16.so
    10 9051e8eb6a07a2b10298f4dc2342671854ca432b ima-ng sha256:3d3553312ab91bb95ae7a1620fedcc69793296bdae4e987abc5f8b121efd84b8 /etc/ld.so.cache

PCR: default CONFIG_IMA_MEASURE_PCR_IDX is 10
template-hash: sha1 hash(filedata-hash length, filedata-hash, pathname length, pathname)
filedata-hash: sha256 hash(filedata)


Example 2:  'ima-sig' template (same format as ima-ng, but with an appended signature when present)

    PCR     template-hash                           filedata-hash                           filename-hint                         file-signature
    10 f63c10947347c71ff205ebfde5971009af27b0ba ima-sig sha256:6c118980083bccd259f069c2b3c3f3a2f5302d17a685409786564f4cf05b3939 /usr/lib64/libgspell-1.so.1.0.0   0302046e6c10460100aa43a4b1136f45735669632ad ...
    10 595eb9bf805874b459ce073af158378f274ea961 ima-sig sha256:8632769297867a80a9614caa98034d992441e723f0b383ca529faa306c640638 /usr/lib64/gedit/plugins/libmodelines.so 0302046e6c104601002394b70ab93 ...


Example 3: *original* 'ima' template

    PCR     template-hash                           filedata-hash                           filename-hint
    10 7971593a7ad22a7cce5b234e4bc5d71b04696af4 ima b5a166c10d153b7cc3e5b4f1eab1f71672b7c524 boot_aggregate
    10 2c7020ad8cab6b7419e4973171cb704bdbf52f77 ima e09e048c48301268ff38645f4c006137e42951d0 /init
    10 ef7a0aff83dd46603ebd13d1d789445365adb3b3 ima 0f8b3432535d5eab912ad3ba744507e35e3617c1 /init
    10 247dba6fc82b346803660382d1973c019243e59f ima 747acb096b906392a62734916e0bb39cef540931 ld-2.9.so
    10 341de30a46fa55976b26e55e0e19ad22b5712dcb ima 326045fc3d74d8c8b23ac8ec0a4d03fdacd9618a ld.so.cache

PCR: default CONFIG_IMA_MEASURE_PCR_IDX is 10
template-hash: sha1 hash(filedata-hash, filename-hint)
filedata-hash: sha1 hash(filedata)

The first element in the runtime measurement list, shown above, is the boot_aggregate. The boot_aggregate is a SHA1 hash over tpm registers 0-7, assuming a TPM chip exists, and zeroes, if the TPM chip does not exist.

- display the bios measurement list entries, used in calculating the boot aggregate

    $ su -c 'head /sys/kernel/security/tpm0/ascii_bios_measurements'

    0 f797cb88c4b07745a129f35ea01b47c6c309cda9 08 [S-CRTM Version]
    0 dca68da0707a9a52b24db82def84f26fa463b44d 01 [POST CODE]
    0 dd9efa31c88f467c3d21d3b28de4c53b8d55f3bc 01 [POST CODE]
    0 dd261ca7511a7daf9e16cb572318e8e5fbd22963 01 [POST CODE]
    0 df22cabc0e09aabf938bcb8ff76853dbcaae670d 01 [POST CODE]
    0 a0d023a7f94efcdbc8bb95ab415d839bdfd73e9e 01 [POST CODE]
    0 38dd128dc93ff91df1291a1c9008dcf251a0ef39 01 [POST CODE]
    0 dd261ca7511a7daf9e16cb572318e8e5fbd22963 01 [POST CODE]
    0 df22cabc0e09aabf938bcb8ff76853dbcaae670d 01 [POST CODE]
    0 a0d023a7f94efcdbc8bb95ab415d839bdfd73e9e 01 [POST CODE]

### Verifying IMA Measurements

The IMA tests programs are part of the [Linux Test Project.](https://github.com/linux-test-project/ltp/wiki)

- Download, compile, and install the standalone version of the IMA LTP test programs in /usr/local/bin.

    $ wget -O ltp-ima-standalone-v2.tar.gz http://downloads.sf.net/project/linux-ima/linux-ima/ltp-ima-standalone-v2.tar.gz
    $ tar -xvzf ltp-ima-standalone-v2.tar.gz
    ima-tests/Makefile
    ima-tests/README
    ima-tests/ima_boot_aggregate.c
    ima-tests/ima_measure.c
    ima-tests/ima_mmap.c
    ima-tests/ima_sigv2.c
    ima-tests/ltp-tst-replacement.c
    ima-tests/pkeys.c
    ima-tests/rsa_oid.c
    ima-tests/config.h
    ima-tests/debug.h
    ima-tests/hash_info.h
    ima-tests/ima_sigv2.h
    ima-tests/list.h
    ima-tests/pkeys.h
    ima-tests/rsa.h
    ima-tests/test.h
    $ cd ima-tests
    $ make
    $ su -c 'make install'

- ima_boot_aggregate <tpm_bios file>

Using the TPM's binary bios measurement list, re-calculate the boot aggregate.

    $ su -c '/usr/local/bin/ima_boot_aggregate /sys/kernel/security/tpm0/binary_bios_measurements'
    000 f797cb88c4b07745a129f35ea01b47c6c309cda9
    000 dca68da0707a9a52b24db82def84f26fa463b44d
    < snip >
    005 6895eb784cdaf843eaad522e639f75d24d4c1ff5
    PCR-00: 07274edf7147abda49200100fd668ce2c3a374d7
    PCR-01: 48dff4fbf3a34d56a08dfc1504a3a9d707678ff7
    PCR-02: 53de584dcef03f6a7dac1a240a835893896f218d
    PCR-03: 3a3f780f11a4b49969fcaa80cd6e3957c33b2275
    PCR-04: acb44e9dd4594d3f121df2848f572e4d891f0574
    PCR-05: df72e880e68a2b52e6b6738bb4244b932e0f1c76
    PCR-06: 585e579e48997fee8efd20830c6a841eb353c628
    PCR-07: 3a3f780f11a4b49969fcaa80cd6e3957c33b2275
    boot_aggregate:b5a166c10d153b7cc3e5b4f1eab1f71672b7c524

and compare the value with the ascii_runtime_measurement list value.

    $ su -c 'cat /sys/kernel/security/ima/ascii_runtime_measurements | grep boot_aggregate'
    10 7971593a7ad22a7cce5b234e4bc5d71b04696af4 ima b5a166c10d153b7cc3e5b4f1eab1f71672b7c524 boot_aggregate

<br>

- ima_measure <binary_runtime_measurements> \[--validate\] \[--verify\] \[--verbose\]

using the IMA binary measurement list, calculate the PCR aggregate value

    $ su -c '/usr/local/bin/ima_measure /sys/kernel/security/ima/binary_runtime_measurements --validate'
    PCRAggr (re-calculated): B4 D1 93 D8 FB 31 B4 DD 36 5D DA AD C1 51 AC 84 FA 88 78 1B

and compare it against the PCR value

    $ cat /sys/devices/pnp0/00:0a/pcrs | grep PCR-10
    PCR-10: B4 D1 93 D8 FB 31 B4 DD 36 5D DA AD C1 51 AC 84 FA 88 78 1B

### IMA re-measuring files

Part of the TCG requirement is that all Trusted Computing Base (TCB) files be measured, and re-measured if the file has changed, before reading/executing the file. IMA detects file changes based on i_version. To re-measure a file after it has changed, the filesystem must support i_version and, if needed, be mounted with i_version (eg. ext3, ext4).  Not all filesystems require the explicit mount option.   With commit a2a2c3c8580a ("ima: Use i_version only when filesystem supports it") i_version is considered an optimization.  If i_version is not enabled, either because the local filesystem does not support it or the filesystem was not mounted with i_version, the file will now always be re-measured, whether or not the file changed, but only new measurements will be added to the measurement list.

-   Attempt to mount a filesystem with i_version support.

        $ su -c 'mount -o remount,rw,iversion /home'

        mount: you must specify the filesystem type

    Attempt to remount '/home' with i_version support, shown above, failed. Please install a version of the [util-linux-ng-2.15-rc1](http://www.kernel.org/pub/linux/utils/util-linux-ng/v2.15/ "http://www.kernel.org/pub/linux/utils/util-linux-ng/v2.15/") package or later.

-   To automatically mount a filesystem with i_version support, update /etc/fstab.

        UUID=blah  /home                   ext3    defaults,iversion

-   Mount the root filesystem with i_version.
    -   For systems with /etc/rc.sysinit, update the mount options
        adding 'iversion':

            # Remount the root filesystem read-write.
            update_boot_stage RCmountfs
            if remount_needed ; then
              action $"Remounting root filesystem in read-write mode: " mount -n -o remount,rw,iversion /
            fi

    -   For systems using dracut, root 'mount' options can be specified on the boot
        command line using 'rootflags'. Add 'rootflags=i_version'. Unlike 'mount',
        which expects 'iversion', notice that on the boot command line 'i_version'
        contains an underscore.

### Linux-audit support

As of [Linux-audit](http://people.redhat.com/sgrubb/audit/ "http://people.redhat.com/sgrubb/audit/") 2.0, support for integrity auditing messages is available.

### Defining an LSM specific policy

The ima_tcb default measurement policy in linux-2.6.30 measures all system sensitive files - executables, mmapped libraries, and files opened for read by root. These measurements, the measurement list and the aggregate integrity value, can be used to attest to a system's
runtime integrity. Based on these measurements, a remote party can detect whether critical system files have been modified or if malicious software has been executed.

Default policy

    dont_measure fsmagic=PROC_SUPER_MAGIC
    dont_measure fsmagic=SYSFS_MAGIC
    dont_measure fsmagic=DEBUGFS_MAGIC
    dont_measure fsmagic=TMPFS_MAGIC
    dont_measure fsmagic=SECURITYFS_MAGIC
    dont_measure fsmagic=SELINUX_MAGIC
    measure func=BPRM_CHECK
    measure func=FILE_MMAP mask=MAY_EXEC

    < add LSM specific rules here >

    measure func=PATH_CHECK mask=MAY_READ uid=0

But not all files opened by root for read, are necessarily part of the Trusted Computing Base (TCB), and therefore do not need to be measured. Linux Security Modules (LSM) maintain file metadata, which can be leveraged to limit the number of files measured.

Examples: adding LSM specific rules

    SELinux:
    dont_measure obj_type=var_log_t
    dont_measure obj_type=auditd_log_t

    Smack:
    measure subj_user=_ func=INODE_PERM mask=MAY_READ

To replace the default policy 'cat' the custom IMA measurement policy and redirect the output to "< securityfs >/ima/policy".  Both dracut and systemd have been modified to load the custom IMA policy.  If the IMA policy contains LSM labels, then the LSM policy must be loaded prior to the IMA policy. (eg. if systemd loads the SELinux policy, then systemd must also load the IMA policy.)

systemd commit c8161158 adds support for loading a custom IMA measurement policy.  Simply place the custom IMA policy in /etc/ima/ima-policy.  systemd will automatically load the custom policy.

dracut commit 0c71fb6 add initramfs support for loading the custom IMA measurement policy. Build and install dracut (git://git.kernel.org/pub/scm/boot/dracut/dracut.git), to load the custom IMA measurement policy(default: /etc/sysconfig/ima-policy).

For more information on defining an LSM specific measurement/appraisal/audit policy, refer to the kernel Documentation/ABI/testing/ima_policy.


## IMA-appraisal

IMA currently maintains an integrity measurement list used for remote attestation. The IMA-appraisal extension adds local integrity validation and enforcement of the measurement against a "good" value stored as an extended attribute 'security.ima'. The initial method for validating 'security.ima' are hashed based, which provides file data integrity, and digital signature based, which in addition to providing file data integrity, provides authenticity.

### Enabling IMA-appraisal

IMA-appraisal was upstreamed in Linux 3.7.  For distros that enable IMA-appraisal by default in their kernels, appraising file measurements requires rebooting the kernel first with the boot command line parameters 'ima_appraise_tcb' and ima_appraise='fix' to [label the filesystem](#labeling-the-filesystem-with-securityima-extended-attributes). Once labeled, reboot with just the 'ima_appraise_tcb' boot command line parameter.

Refer to [compiling the kernel](#compiling-the-kernel-with-evmima-appraisal-enabled) for directions on configuring and building a new kernel with IMA-appraisal support enabled.

### Understanding the IMA-appraisal policy

The IMA-appraisal policy extends the measurement policy ABI with two new keywords: appraise/dont_appraise. The default appraise policy appraises all files owned by root. Like the default measurement policy, the default appraisal policy does not appraise pseudo filesystem files (eg. debugfs, tmpfs, securityfs, or selinuxfs.)

Additional rules can be added to the default IMA measurement/appraisal policy, which take advantage of the SELinux labels, for a more fine grained policy. Refer to Documentation/ABI/testing/ima_policy.

### Labeling the filesystem with 'security.ima' extended attributes

A new boot parameter 'ima_appraise=' has been defined in order to label existing file systems with the 'security.ima' extended attribute.

-   ima_appraise= appraise integrity measurements\
     Format: { "off" | "log" | "fix" } \


off - is a runtime parameter that turns off integrity appraisal verification.
enforce - verifies and enforces runtime file integrity. \[default\]
fix - for non-digitally signed files, updates the 'security.ima' xattr to reflect the existing file hash.


After building a kernel with IMA-appraisal enabled and verified that the filesystems are mounted with [i_version](#ima-re-measuring-files) support, to label the filesystem, reboot with the boot command line options 'ima_appraise_tcb' and 'ima_appraise=fix'. Opening a file owned by root, will cause the 'security.ima' extended attributes to be written. For example, to label the entire filesystem, execute:

`find / \\( -fstype rootfs -o ext4 -type f \\) -uid 0 -exec head -n 1
'{}' >/dev/null \\;`

### Labeling 'immutable' files with digital signatures

'Immutable' files, such as ELF executables, can be digitally signed, storing the digital signature in the 'security.ima' xattr. Creating the digital signature requires generating an RSA private/public key pair. The private key is used to sign the file, while the public key is used to verify the signature. For example, to digitally sign all kernel modules, replace <RSA private key>, below, with the pathname to your RSA private key, and execute:

`find /lib/modules -name "\*.ko" -type f -uid 0 -exec evmctl sign --imasig '{}' <RSA private key> \;`

evmctl manual page is here [evmctl.1.html](http://linux-ima.sourceforge.net/evmctl.1.html)

### Running with IMA-appraisal

Once the filesystem has been properly labeled, before rebooting, re-install the new labeled kernel.  Modify the [initramfs](#building-an-initramfs-to-load-keys) to load the RSA public key on the IMA keyring, using evmctl. Reboot with the 'ima_appraise_tcb' and, possibly, the 'rootflags=i_version' options.

## Extending trusted and secure boot to the OS

( Place holder )

### Including file signatures in the measurement list

The 'ima-sig' template, in addition to the file data hash and the full pathname, includes the file signature, as stored in the 'security.ima' extended attribute.

    10 d27747646f317e3ca1205287d0615073fe676bc6 ima-sig sha1:08f8f20c14e89da468bb238
    d2012c9458ae67f6a /usr/bin/mkdir 030202afab451100802b22e3ed9f6a70fb5babf030d1181
    8152b493bd6bfd916005fad7fdcfd7f88d43f6cffaf6fd1ea3b75032dd702b661d4717729e4a3fa4
    ee95a47f239955491fc8064eca8cb96302d305d59750ae4ffde0a5f615f910475eee72ae0306e4ae
    0269d7d04af2a485898eec3286795d621e83b7dedc99f5019b7ee49b189f3ded0a2

    # getfattr -m ^security --dump -e hex /usr/bin/mkdir
    # file: usr/bin/mkdir
    security.evm=0x0238b0cdd9e97d5bed3bcde5a4793ef8da6fe7c7cc
    security.ima=0x030202afab451100802b22e3ed9f6a70fb5babf030d11818152b493bd6bfd916005fad
    7fdcfd7f88d43f6cffaf6fd1ea3b75032dd702b661d4717729e4a3fa4ee95a47f239955491fc8064eca8cb
    96302d305d59750ae4ffde0a5f615f910475eee72ae0306e4ae0269d7d04af2a485898eec3286795d621e8
    3b7dedc99f5019b7ee49b189f3ded0a2


### Signing IMA-appraisal keys

( Place holder )

## IMA-audit

IMA-audit includes file hashes in the audit log, which can be used to augment existing system security analytics/forensics. IMA-audit extends the IMA policy ABI with the policy action keyword - "audit".

Example policy to audit  executable file hashes

    audit func=BPRM_CHECK



## Linux Extended Verification Module (EVM)

EVM detects offline tampering of the security extended attributes (e.g. security.selinux, security.SMACK64, security.ima), which is the basis for LSM permission decisions and, with the IMA-appraisal extension, integrity appraisal decisions. EVM provides a framework, and two methods for detecting offline tampering of the security extended attributes. The initial method maintains an HMAC-sha1 across a set of security extended attributes, storing the HMAC as the extended attribute 'security.evm'. The other method is based on a digital signature of the security extended attributes hash. To verify the integrity of an extended attribute, EVM exports evm_verifyxattr(), which re-calculates either the HMAC or the hash, and compares it with the version stored in 'security.evm'.

### Enabling EVM

EVM was upstreamed in Linux 3.2. EVM-digital-signatures is currently in the Linux 3.3 release candidate.

Refer to [compiling the kernel](#compiling-the-kernel-with-evmima-appraisal-enabled), for directions on configuring and building a new kernel with EVM support.

### Running EVM

EVM is configured automatically to protect standard “security” extended attributes:

-   security.ima (IMA's stored “good” hash for the file)
-   security.selinux (the selinux label/context on the file)
-   security.SMACK64 (Smack's label on the file)
-   security.capability (Capability's label on executables)

EVM protects the configured extended attributes with an HMAC across their data, keyed with an EVM key provided at boot time. EVM looks for this key named 'evm-key' on root's key ring. Refer to [trusted and EVM encrypted keys](#creating-trusted-and-evm-encrypted-keys), for directions on creating EVM keys. Once loaded, EVM can be activated by writing a '1' to the evm securityfs file: `**echo "1" >/sys/kernel/security/evm**`

Before EVM is activated, any requested integrity appraisals are unknown, so the EVM startup should be done early in the boot process, preferably entirely within the kernel and initramfs (which are measured by trusted grub) and before any reference to the real root filesystem. To build an initramfs with EVM enabled, build and install dracut (git://git.kernel.org/pub/scm/boot/dracut/dracut.git), which contains the trusted and EVM dracut modules.

### Labeling the filesystem with 'security.evm'

A new boot parameter 'evm=fix' has been defined in order to label existing file systems with the 'security.evm' extended attribute.

After building a kernel with EVM, IMA-appraisal, and trusted and encrypted keys enabled, installed the trusted and EVM dracut modules, created the EVM key, and verified that the filesystems are mounted, including root, with [i_version](#ima-re-measuring-files) support, to label the filesystem, reboot with the command line options 'ima_tcb', 'ima_appraise_tcb', 'ima_appraise=fix', 'evm=fix' and, possibly, 'rootflags=i_version'.

Once EVM is started, as existing file metadata changes or as new files are created, EVM assumes that the LSM has approved such changes, and automatically updates the HMACs accordingly, assuming the existing value is valid. In fix mode, opening a file owned by root, will fix the 'security.ima' extended attribute, causing the 'security.evm' extended attribute to be written as well, regardless if the existing security 'ima' or 'evm' extended attributes are valid. To label the entire filesystem, execute:

`find / -fstype ext4 -type f -uid 0 -exec head -n 1 '{}' >/dev/null \;`

The following sign_file script can be used to label all 'ELF' files with EVM and IMA digital signatures, and all other files with just an EVM digital signature.

sign_file:

    #!/bin/sh
    #label "immutable" files with EVM/IMA digital signatures
    #label everything else with just EVM digital signatures

    file $1 | grep 'ELF' > /dev/null
    if [ $? -eq 0 ]; then
         evmctl sign --imasig $1 /home/zohar/privkey_evm.pem
    else
         evmctl sign --imahash $1 /home/zohar/privkey_evm.pem
    fi

Instead of opening the file using head, digitally sign the files:

`find / \( -fstype rootfs -o -fstype ext3 -o -fstype ext4 \) -type f -exec sign_file.sh {} \;`


Once the filesystem has been properly labeled, before rebooting, re-install the new labeled kernel. Modify the initramfs to load the RSA public keys on the EVM and IMA keyring. Reboot with just the 'ima_tcb', 'ima_appraise_tcb' and, possibly, 'rootflags=i_version' options.

## Compiling the kernel with EVM/IMA-appraisal enabled

For those unfamiliar with building a linux kernel, here is a short list of existing websites.

-   [http://kernelnewbies.org/KernelBuild](http://kernelnewbies.org/KernelBuild "http://kernelnewbies.org/KernelBuild")
-   [http://fedoraproject.org/wiki/BuildingUpstreamKernel](http://fedoraproject.org/wiki/BuildingUpstreamKernel "http://fedoraproject.org/wiki/BuildingUpstreamKernel")
-   [https://wiki.ubuntu.com/KernelTeam/GitKernelBuild](https://wiki.ubuntu.com/KernelTeam/GitKernelBuild "https://wiki.ubuntu.com/KernelTeam/GitKernelBuild")

###  Configuring the kernel

Depending on the distro, some of these options might already be enabled, but not necessarily as builtin.  For distros with recent kernels, download the distro's kernel source and recompile the kernel with the additional .config options, below.  (Refer to the distro's documentation for building and installing the kernel from source.)

For IMA, enable the following .config options:

    CONFIG_INTEGRITY=y
    CONFIG_IMA=y
    CONFIG_IMA_MEASURE_PCR_IDX=10
    CONFIG_IMA_AUDIT=y
    CONFIG_IMA_LSM_RULES=y

For IMA-appraisal, enable the following .config options:

    CONFIG_INTEGRITY_SIGNATURE=y
    CONFIG_INTEGRITY=y
    CONFIG_IMA_APPRAISE=y

EVM has a dependency on encrypted keys, which should be encrypted/decrypted using a trusted key. For those systems without a TPM, the EVM key could be encrypted/decrypted with a user-defined key instead.  For EVM, enable the following .config options:

    CONFIG_TCG_TPM=y

    CONFIG_KEYS=y
    CONFIG_TRUSTED_KEYS=y
    CONFIG_ENCRYPTED_KEYS=y

    CONFIG_INTEGRITY_SIGNATURE=y
    CONFIG_INTEGRITY=y
    CONFIG_EVM=y

For the new 'ima-ng'/'ima-sig' template support(linux 3.13), clone the stable tree.

    $ cd ~/src/kernel
    $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git

    $ cd linux-stable
    $ git remote update
    $ git checkout --track -b linux-3.13.y origin/linux-3.13.y

and enable these additional .config options:

    CONFIG_IMA_NG_TEMPLATE=y
    CONFIG_IMA_DEFAULT_TEMPLATE="ima-ng"
    CONFIG_IMA_DEFAULT_HASH_SHA256=y


###  Installing the new kernel

If enabling EVM, before installing the new kernel, follow the directions for creating the EVM encrypted key (#creating_trusted_and_evm_encrypted keys) and EVM/IMA public keys (#creating_and_loading_the_evm_and_ima_publicprivate_keypairs).

Install the kernel as normal.

    $ su -c "make modules_install install"

## Creating trusted and EVM encrypted keys

Trusted and encrypted keys are two new key types (upstreamed in 2.6.38) added to the existing kernel key ring service. Both of these new types are variable length symmetic keys and, in both cases, are created in the kernel. User space sees, stores, and loads only encrypted blobs. Trusted Keys require the availability of a Trusted Platform Module (TPM) chip for greater security, while encrypted keys can be used on any system. All user level blobs, are displayed and loaded in hex ascii for convenience, and are integrity verified.

Depending on the distro, trusted and encrypted keys might not be enabled. Refer to [compiling the kernel](#compiling-the-kernel-with-evmima-appraisal_enabled), for directions on configuring and building a new kernel with trusted and encrypted key support.

The trusted and EVM dracut modules, by default, looks for the trusted and EVM encrypted keys in /etc/keys. To create and save the kernel master and EVM keys,

    $ su -c 'mkdir -p /etc/keys'

    # To create and save the kernel master key (trusted type):
    $ su -c 'modprobe trusted encrypted'
    $ su -c 'keyctl add trusted kmk-trusted "new 32" @u'
    $ su -c 'keyctl pipe `keyctl search @u trusted kmk-trusted` >/etc/keys/kmk-trusted.blob'

    # Create the EVM encrypted key
    $ su -c 'keyctl add encrypted evm-key "new trusted:kmk-trusted 32" @u'
    $ su -c 'keyctl pipe `keyctl search @u encrypted evm-key` >/etc/keys/evm-trusted.blob'

For those systems which don't have a TPM, but want to experiment with EVM, create a user key of 32 random bytes, and an EVM user encrypted key. Unlike trusted/encrypted keys, user type key data is visible to userspace.

    $ su -c 'mkdir -p /etc/keys'

    # To create and save the kernel master key (user type):
    $ su -c 'modprobe trusted encrypted'
    $ su -c 'keyctl add user kmk-user "`dd if=/dev/urandom bs=1 count=32 2>/dev/null`" @u'
    $ su -c 'keyctl pipe `keyctl search @u user kmk-user` > /etc/keys/kmk-user.blob'

    # Create the EVM encrypted key
    $ su -c 'keyctl add encrypted evm-key "new user:kmk-user 32" @u'
    $ su -c 'keyctl pipe `keyctl search @u encrypted evm-key` >/etc/keys/evm-user.blob'

Update /etc/sysconfig/masterkey to reflect using a 'user-defined' master key type.

    MULTIKERNELMODE="NO"
    MASTERKEYTYPE="user"
    MASTERKEY="/etc/keys/kmk-${MASTERKEYTYPE}.blob"

Similarly update /etc/sysconfig/evm or on the boot command line specify the EVM key filename (eg. 'evmkey=/etc/keys/evm-user.blob'.)
<br>
## Creating and loading the EVM and IMA public/private keypairs
### Digital Signatures: generating an RSA public/private key pair

    # generate unencrypted private key
    openssl genrsa -out privkey_evm.pem 1024

    # or generate encrypted (password protected) private key
    openssl genrsa -des3 -out privkey_evm.pem 1024

    # or convert unencrypted key to encrypted on
    openssl rsa -in /etc/keys/privkey_evm.pem -out privkey_evm_enc.pem -des3
    or
    openssl pkcs8 -topk8 -in /etc/keys/privkey_evm.pem -out privkey_evm_enc.pem

    openssl rsa -pubout -in privkey_evm.pem -out pubkey_evm.pem

### ima-evm-utils: installing the package from source

ima-evem-utils is used to sign files, using the private key, and to load the public keys on the ima/evm keyrings.  ima-evm-utils can be cloned from git repo with the following command:

    git clone git://linux-ima.git.sourceforge.net/gitroot/linux-ima/ima-evm-utils.git
    cd ima-evm-utils
    ./autogen.sh
    ./configure
    make
    sudo make install

evmctl manual page is here [evmctl.1.html](http://linux-ima.sourceforge.net/evmctl.1.html)

### IMA/EVM keyrings: loading the public keys

    ima_id=`keyctl newring _ima @u`
    evmctl import /etc/keys/pubkey_ima.pem $ima_id

    evm_id=`keyctl newring _evm @u`
    evmctl import /etc/keys/pubkey_evm.pem $evm_id

## Building an initramfs to load keys

Modify the initramfs to load the EVM encrypted key and the EVM/IMA public keys on their respective keyrings.

### dracut

Dracut commits 0c71fb6 and e1ed2a2 add support for loading the masterkey and the EVM encrypted key, not the EVM/IMA public keys (todo).

    0c71fb6 dracut: added new module integrityy
    e1ed2a2 dracut: added new module masterkey

Clone dracut (git://git.kernel.org/pub/scm/boot/dracut/dracut.git). By default, the masterkey and integrity modules are not enabled in the dracut git tree.  Edit module-setup in both directories, changing the check() return value to 0.  'make' and 'install' dracut.

Create an initramfs:

    # dracut -H -f /boot/initramfs-<kernel> <kernel> -M

And add a grub2 menu entry:

    # grub2-mkconfig -o /boot/grub2/grub.cfg


### initramfs-tools

To enable IMA/EVM in initramfs-tools it is necessary to add just 2 files to /etc/initramfs-tools directory.

/etc/initramfs-tools/hooks/ima.sh:

    #!/bin/sh

    echo "Adding IMA binaries"

    . /usr/share/initramfs-tools/hook-functions

    copy_exec /etc/keys/evm-key
    copy_exec /etc/keys/pubkey_evm.pem
    copy_exec /etc/ima_policy
    copy_exec /bin/keyctl
    copy_exec /usr/bin/evmctl /bin/evmctl

/etc/initramfs-tools/scripts/local-top/ima.sh:

    #!/bin/sh -e

    PREREQ=""

    # Output pre-requisites
    prereqs()
    {
            echo "$PREREQ"
    }

    case "$1" in
        prereqs)
            prereqs
            exit 0
            ;;
    esac

    grep -q "ima=off" /proc/cmdline && exit 1

    mount -n -t securityfs securityfs /sys/kernel/security

    IMA_POLICY=/sys/kernel/security/ima/policy
    LSM_POLICY=/etc/ima_policy

    grep -v "^#" $LSM_POLICY >$IMA_POLICY

    # import EVM HMAC key
    keyctl show |grep -q kmk || keyctl add user kmk "testing123" @u
    keyctl add encrypted evm-key "load `cat /etc/keys/evm-key`" @u
    #keyctl revoke kmk

    # import Module public key
    mod_id=`keyctl newring _module @u`
    evmctl import /etc/keys/pubkey_evm.pem $mod_id

    # import IMA public key
    ima_id=`keyctl newring _ima @u`
    evmctl import /etc/keys/pubkey_evm.pem $ima_id

    # import EVM public key
    evm_id=`keyctl newring _evm @u`
    evmctl import /etc/keys/pubkey_evm.pem $evm_id

    # enable EVM
    echo "1" > /sys/kernel/security/evm

    # enable module checking
    #echo "1" > /sys/kernel/security/module_check


generate new initramfs:

    update-initramfs -k 3.4.0-rc5-kds+ -u

Edit GRUB bootloader /boot/grub/custom.cfg:

    menuentry 'IMA' {
        set gfxpayload=$linux_gfx_mode
        insmod gzio
        insmod part_msdos
        insmod ext2
        set root='(hd0,msdos1)'
        # add following string to kernel command line to enable "fix" mode: "ima_appraise=fix evm=fix"
        linux   /boot/vmlinuz-3.4.0-rc5-kds+ root=/dev/sda1 ro nosplash ima_audit=1 ima_tcb=1 ima_appraise_tcb=1
        initrd  /boot/initrd.img-3.4.0-rc5-kds+
    }

## IMA policy examples
### Builtin policys

**Enabled on the boot command line:**

*ima_tcb* - measures all files read as root and all files executed
*ima_appraise_tcb* - appraises all files owned by root

### audit log all executables

    # audit log all executables
    audit func=BPRM_CHECK mask=MAY_EXEC

### Measure nothing, appraise everything

    #
    # Integrity measure policy
    #
    # Do not measure anything, but appraise everything
    #
    # PROC_SUPER_MAGIC
    dont_appraise fsmagic=0x9fa0
    # SYSFS_MAGIC
    dont_appraise fsmagic=0x62656572
    # DEBUGFS_MAGIC
    dont_appraise fsmagic=0x64626720
    # TMPFS_MAGIC
    dont_appraise fsmagic=0x01021994
    # RAMFS_MAGIC
    dont_appraise fsmagic=0x858458f6
    # DEVPTS_SUPER_MAGIC
    dont_appraise fsmagic=0x1cd1
    # BIFMT
    dont_appraise fsmagic=0x42494e4d
    # SECURITYFS_MAGIC
    dont_appraise fsmagic=0x73636673
    # SELINUXFS_MAGIC
    dont_appraise fsmagic=0xf97cff8c
    appraise


## ima-evm-utils

ima-evm-utils package provides the *evmctl* utility that can be used for producing and verifying digital signatures, which are used by Linux kernel integrity subsystem. It can be also used to import keys into the kernel keyring.

evmctl manual page is located here: [http://linux-ima.sourceforge.net/evmctl.1.html](http://linux-ima.sourceforge.net/evmctl.1.html)


<br>

## Using IMA/EVM on Android

Enabling IMA/EVM is not very difficult task but involves few tricky steps related to file system creation and labeling.

Android source code is kept in GIT repositories and usually downloaded using 'repo' tool.

IMA/EVM support was implemented using Android 5.0.2 source tree and tested on Huawei P8.

Set of patches is located [here](https://sourceforge.net/projects/linux-ima/files/Android%20patches/).

### Kernel configuration

Kernel source code is usually located in the 'kernel' folder in the root of the Android source tree.
Huawei P8 runs on HiSilicon Kirin 930/935 64 bit ARM CPU.

Default kernel configuration file is 'kernel/arch/arm64/configs/hisi_3635_defconfig'

Following lines were added:

	# Integrity
	CONFIG_INTEGRITY=y
	CONFIG_IMA=y
	CONFIG_IMA_MEASURE_PCR_IDX=10
	CONFIG_IMA_AUDIT=y
	CONFIG_IMA_LSM_RULES=y
	CONFIG_INTEGRITY_SIGNATURE=y
	CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
	CONFIG_IMA_APPRAISE=y
	CONFIG_EVM=y

	# Keys
	CONFIG_KEYS=y
	CONFIG_KEYS_DEBUG_PROC_KEYS=y
	CONFIG_TRUSTED_KEYS=y
	CONFIG_ENCRYPTED_KEYS=y



### Kernel command line parameters

Kernel command line parameters are usually specified in board configuration files, such as BoardConfig.mk, for example, 'device/hisi/hi3635/BoardConfig.mk

Add following lines to the file:

	BOARD_KERNEL_CMDLINE += ima_audit=1
	BOARD_KERNEL_CMDLINE += ima_tcb ima_appraise_tcb
	# enable fix mode while testing
	BOARD_KERNEL_CMDLINE += ima_appraise=fix evm=fix


### IMA boot initialization

To boot Android, devices usually have boot partition which is flashed with boot.img.
boot.img consist of the kernel and compressed ramdisk which includes Android root filesystem.
boot.img is usually protected using digital signature which is verified by the Android bootloader as a part of Secure Boot process.

Root filesystem contains Android 'init' system and minimal set of tools, which is required to initialize and mount rest of filesystems, including '/system' and '/data'.

Android uses own 'init' system (system/core/init) which reads configuration from '/init.rc' and multiple sourced '/init.*.rc' scripts located in the root folder.

We used to use shell scripts to load IMA/EVM keys and policy. On desktop systems there is no limitation on ramdisk size, but on Android devices it is limited by the size of the boot partition. Android ramdisk/root filesystem does not include shell, but including adding shell, keyctl, evmctl makes ramdisk so big so that boot.img does not fit to the boot partition.

For that reason it was necessary to implement IMA/EVM initialization functionality as native program 'ima-init'.

This patch ([0004-ima_init-tool-to-load-IMA-EVM-keys-and-policy.patch](http://sourceforge.net/projects/linux-ima/files/Android%20patches/0004-ima_init-tool-to-load-IMA-EVM-keys-and-policy.patch/view)) adds 'system/extras/ima-init' project to the Android source tree. It builds '/ima-init' initialization program and generates private and public keys to sign filesystem image usign EVM signatures and verify them during runtime.

ima-init project also includes 'ima_key_gen.sh' script to generate keys and certificates and also basic 'ima_policy', which needs to be changed based on the particular need.

ima-init and public keys are included in the ramdisk root filesystem.

In order to initialize IMA/EVM it is necessary add like following configuration to relevant init.rc file:

	service ima /sbin/ima_init
	    class main
	    user root
	    group root
	    disabled
	    seclabel u:r:init:s0
	    oneshot

Above example add 'ima' service which is used to initialize IMA.

IMA service needs to be started using 'start ima' before mounting any real filesystem. For example it was added to the 'on fs' target before mounting 'system' partition.

	on fs
	    mount securityfs none /sys/kernel/security
	    start ima

	    wait /dev/block/mmcblk0p38
	    mount ext4 /dev/block/mmcblk0p38 /system ro

	    wait /dev/block/mmcblk0p40
	    mount ext4 /dev/block/mmcblk0p40 /data nosuid nodev noatime data=ordered,i_version


### Mounting filesystems (with iversion)

In order IMA would update 'security.ima' when file changes, it is necessary to mount filesystems with i_version support. Android usually mounts all filesystems in init.rc scripts using 'mount' command. Notice in the example above that '/data' partition is mounted using 'i_version' options.

Desktop mount tool from mount package recognizes iversion option and pass necessary flag to mount system call. Unrecognized options are passed as a string in the last argument of the mount system call to the kernel filesystem module. Kernel filesystem modules recognize 'i_version' option instead of 'iversion'. Thus on the desktop systems it is possible to use both iversion and i_version options.

Android tools do not recognize 'iversion' option. It is necessary to use 'i_version' option.

init.rc 'mount' command options are located after the mount point. All except last are 'init' builtin options and *only* the last option is passed as a string to the mount system call. Thus it is necessary to put 'i_version' option as a last option or to add it to the comma separated option list as above.


### Filesystem labeling

Filesystem labeling with digital signatures has to be done during image creation process. It can be done using two approaches.

The easiest approach is to label ready image. It requires following steps:

1. convert sparse image to normal image using simg2img tool
1. 'loop mount' the image
1. label filesystem using evmctl tool
1. unmount image
1. convert image back to sparse image using img2simg tool

But mount operation would require root privileges to mount filesystem.

Android 'make_ext4fs' tool is used to create filesystem image. It provides support for labeling filesystem using 'security labels' (SELinux). We extended make_ext4fs to compute and set IMA/EVM signatures while creating a filesystem. It uses extended version of 'evmctl' to compute signatures by passing all relevant file metadata using evmctl command line parameters.

Here is a patch that adds IMA/EVM support to the make_ext4fs ([0003-IMA-EVM-labelling-support.patch](http://sourceforge.net/projects/linux-ima/files/Android%20patches/0003-IMA-EVM-labelling-support.patch/view)).


### Additional tools

It is convenient for testing and debugging to have additional tools such as keyctl and getfattr tools on the device.

#### evmctl

For Android, 'evmct' is a host only tool to compute IMA/EVM signatures and convert RSA keys to the kernel binary format.

'evmctl' was extended to pass file metadata using command line parameters:

      --ino          use custom inode for EVM
      --uid          use custom UID for EVM
      --gid          use custom GID for EVM
      --mode         use custom Mode for EVM
      --generation   use custom Generation for EVM(unspecified: from FS, empty: use 0)
      --ima          use custom IMA signature for EVM
      --selinux      use custom Selinux label for EVM
      --caps         use custom Capabilities for EVM(unspecified: from FS, empty: do not use)


#### keyctl

This patch ([0002-keyctl-tool.patch](http://sourceforge.net/projects/linux-ima/files/Android%20patches/0002-keyctl-tool.patch/view)) adds project system/extras/keyctl.

#### getfattr

This patch ([0001-getfattr-tool.patch](http://sourceforge.net/projects/linux-ima/files/Android%20patches/0001-getfattr-tool.patch/view)) adds project system/extras/getfattr.

<br>

## Frequently asked questions

-   Why is the first entry in the IMA measurement list (/sys/kernel/security ima/ascii_runtime_measurements) are 0's?

    The first entry is the TPM boot aggregate containing PCR values 0 -
    7. Enable the TPM in BIOS and take ownership.

-   How do I take ownership of the TPM?

    To take ownership of the TPM, download the tpm-tools, start tcsd (eg. 'service tcsd start'), and execute "tpm_takeownership -u -z". This will set the SRK key to the well-known secret(20 zeroes) and prompt for the TPM owner password.

-   Why are there 0x00 entries in the measurement list?

    The measurement list is invalidated, when a regular file is opened for read and, at the same time, opened for write. In the majority of cases, these files should not have been measured in the first place (eg. log files). In other cases, the application needs to be fixed.

-   Why aren't files re-measured and added to the IMA measurement list
    after being updated?

    To detect files changing, the filesystem needs to be mounted with i_version support. For the root filesystem, either update /etc/rc.sysinit or add 'rootflags=i_version' boot command line option. For all other filesystems, modify /etc/fstab.

-   Why doesn't the measurement list verify?

    On some systems, after a suspend/resume, the TPM measurement list does not verify. On those systems, add the boot command line option "tpm.suspend_pcr=< unused PCR >".

-   Why are there two /init entries in the measurement list?

    The first '/init' is from the initramfs. The second /init is from the root filesystem (eg. /sbin/init). The IMA ng/nglong template patches will provide additional metadata to help correlate measurement entries and files.

-   Why am I unable to boot the new EVM/IMA-appraisal enabled kernel?

    After building a new kernel with EVM/IMA-appraisal enabled, the filesystem must be labeled with 'security.evm' and 'security.ima' extended attributes. After creating an [EVM
    key](#creating_trusted_and_evm_encrypted_keys), boot the new kernel with the 'ima_tcb', 'evm=fix', 'ima_appraise_tcb', 'ima_appraise=fix', and, possibly, 'rootflags=i_version' boot
    command line options. Refer to [labeling the filesystem](#labeling-the-filesystem-with-securityima-extended-attributes) with 'security.evm'.

-   How do I enable the measurement policy for local/remote attestation, without enabling IMA-appraisal?

    Boot with the 'ima_tcb' command line option.

-   How do I enable the appraise policy, without the measurement policy?

    Boot with the 'ima_appraise_tcb' command line option.

## Links

-   IMA/EVM utils man page:
    [http://linux-ima.sourceforge.net/evmctl.1.html](http://linux-ima.sourceforge.net/evmctl.1.html)
-   Linux IMA project page:
    [https://sourceforge.net/projects/linux-ima/](https://sourceforge.net/projects/linux-ima/ "https://sourceforge.net/projects/linux-ima/")
-   Old web site:
    [http://linux-ima.sourceforge.net/](http://linux-ima.sourceforge.net/ "http://linux-ima.sourceforge.net/")
-   GIT repositories:
    [https://sourceforge.net/p/linux-ima/ima-evm-utils](https://sourceforge.net/p/linux-ima/ima-evm-utils/)

[Old](/apps/mediawiki/linux-ima/index.php?title=Main_Page_OLD "Old")

Converted from http://sourceforge.net/apps/mediawiki/linux-ima/index.php?title=Main_Page_OLD

[[project_screenshots]]
[[project_admins]]
[[download_button]]
