# 8K Boot Patcher

This is a Docker image to patch the boot partitions of Nokia 8000 or 6300 4G (codenames - Sparkler and Leo) and also on Nokia 2720 Flip and Nokia 800 Tough with locked down firmware (starting from 30.00.17.05). This patch disables basic security checks, updates the ADB daemon to the permanently rooted one, adds statically linked Lua scripting engine and switches SELinux to permissive mode.

## Building

```
docker build -t 8kbootpatcher .
```

## Usage

To patch a boot image, you need to rename it to `boot.img`, copy it into some directory (say, `/path/to/image/dir`) and then run:

```
docker run --rm -it -v /path/to/image/dir:/image 8kbootpatcher
```

Note that you *must* pass the whole path to the image directory starting from the root.

After the process, the `boot.img` file will be patched in place. The original (unpatched) boot image will be copied into `boot-orig.img`.
