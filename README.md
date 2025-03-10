# BandwidthShaper

## Description
This is a small, portable tool to limit bandwidth in Windows. Available for both 32-bit and 64-bit systems.

### License and Compatibility Notice
This application uses [WinDivert](https://reqrypt.org/windivert.html) to accomplish network traffic shaping. WinDivert is licensed under the GNU Lesser General Public License v3 (LGPL v3). You can find the full license text [here](https://github.com/basil00/WinDivert/blob/master/LICENSE).

To comply with LGPL v3, you must separately [download WinDivert](https://github.com/basil00/WinDivert/releases) from its official source and manually copy the required DLL and SYS files to the appropriate directory:
* For 64-bit (x64) applications: Copy `WinDivert.dll` and `WinDivert64.sys` from the **WinDivert x64 folder** to the application's x64 directory.
* For 32-bit (x86) applications: Copy `WinDivert.dll`, `WinDivert32.sys`, and `WinDivert64.sys` from the **WinDivert x86 folder** to the application's x86 directory.

WinDivert itself should support the most recent Windows operating systems, starting from Windows Vista and Windows Server 2008. It does not support older Windows versions like Windows XP. For that, you can use [Traffic Shaper XP](https://www.majorgeeks.com/files/details/traffic_shaper_xp.html) instead.

## Options
Here is the available functionality, which you can also print if you press `-h` or `--help` (or just simply run the executable without any parameters in a CMD):

```
Usage: BandwidthShaper [OPTIONS]
Options:
  -P, --priority <NUM>                         Set WinDivert priority (default: 0, range: -30000 to 30000)
  -p, --process <process1,process2,...>        List of processes to monitor (comma-separated)
  -i, --process-update-interval <NUM>[p|t]     Packet count or time in ms needed for process updates (0 = no update)
  -d, --download <RATE>[b|Kb|KB|Mb|MB|Gb|GB]   Download speed limit per second (default unit: KB)
  -u, --upload <RATE>[b|Kb|KB|Mb|MB|Gb|GB]     Upload speed limit per second (default unit: KB)
  -D, --download-buffer <bytes>                Maximum download buffer size in bytes (default: 150000)
  -U, --upload-buffer <bytes>                  Maximum upload buffer size in bytes (default: 150000)
  -t, --tcp-limit <NUM>                        Maximum limit of active TCP connections (default: 0 = unlimited)
  -r, --udp-limit <NUM>                        Maximum limit of active UDP connections (default: 0 = unlimited)
  -L, --latency <ms>                           Set the latency in milliseconds (default: 0 = no latency)
  -m, --packet-loss <float>                    Set the packet loss in percentage (default: 0.00 = no loss)
  -n, --nic <interface_index>                  Throttle traffic for the specified network interfaces (comma-separated)
            <NIC_INDEX:DL_RATE:UL_RATE>        For different global download and upload rate limits per NIC
  -l, --list-nics                              List all available network interfaces
  -h, --help                                   Display this help message and exit
```

It is only mandatory to give a NIC interface index, and you should also specify at least either the download or the upload speed rate limit. Also **make sure to disable QoS or router-side traffic control if you use this throttling app. Use one or the other, but not both at the same time.** To stop the bandwidth throttling and exit the program, either press "q", Ctrl+C or simply close the CMD window.

If you have any unexpected network issues remaining after closing the CMD window (and not with the q button), then you have to manually stop the driver itself (the program should do this, but if exits uncleanly, this service is going to remain running). You can do this from an elevated command prompt, type the commands:

> sc stop WinDivert\
> sc delete WinDivert

I find that usually the service itself is removed after simply stopping it, so the second command does not do anything, but it does not hurt to also try the `sc delete` command. You can check if WinDivert exists or not with the command:

> sc query WinDivert

And from the WinDivert documentation: "If already running, the WinDivert driver will be automatically uninstalled during the next machine reboot." So you may also just restart your computer and it should go back to normal.

## Usage
First you should use the `--list-nics` option to print all the network interfaces and to check out which interface(s) you want to throttle. Remember its index number and use that for the `-n` parameter. If you want to use multiple network interfaces (e.g. wired and wireless), you can separate the index numbers with a comma. You can also set different global speed rate limits for different network interfaces in the format of: `<NIC_INDEX:DL_RATE:UL_RATE>`. For example: `-n 14,15:0:100KB`. In the earlier example, the *NIC index number 14* will keep using the global download and upload speed limit (what was specified with `-d` and `-u`), and on the *NIC index number 15*, it will have a 100 KB upload rate and unlimited download rate (this always overrides the main global and upload speed limit). You can use 0 to keep either the download or upload speed unlimited here too, if needed.

Using virtual adapters here will most likely break or drastically slow down your network connection, so I recommend to use only your physical interfaces and avoid using virtual machines, as it may make your existing network unusable in a short period of time if there is a virtual machine running, even if you only rate limit your physical interfaces.

If you want to limit the throttling itself to only apply to certain processes, proceed to give their executable filenames after the `-p` parameter, separated by commas. This is optional, if you omit this, the throttling will be global. For example: `-p firefox.exe` or `-p firefox.exe,chrome.exe`. Note that some software already have a built-in speed limiter, such as Steam or torrent clients. Always look in your software or app first for such an option.

If you want these processes to get their PIDs updated, use `-i` (short for interval) with a whole number and a `p` or `t` attached to it. If you did not specify any processes with the `-p` parameter, this is not going to do anything. The default is `-i 0`, which means that the process list will remain as is for the time being. You can either use a packet count or time in ms. A good starting point is `-i 1000p`, or use a higher packet count, like `-i 2000p` or `-i 5000p` if that gets updated too frequently. Alternatively, use a periodic time in ms, e.g. `-i 5000t` for 5 seconds (60000 milliseconds is 1 minute). The reason why this exists is because certain apps may spawn new processes and/or close some of their own. Another reason is if you want to keep monitoring certain processes, since if you close the apps, the traffic shaping will lose effect once you reopen them. If that is not expected to happen (and processes are going to stay as they are), it's best to not specify this option, or you can still explicitly use `-i 0` (which is the default).

Specify the `-d` and `-u` options as you need, for the download and upload speed limit. At least one of the two should be specified. You can use different units for the download and upload rates, as you prefer. If the default KB is not what you need (if you do not specify the unit, it will default to KB), you can also specify it in bytes (b), kilobits (Kb), megabytes (MB), megabits (Mb), gigabytes (GB), gigabits (Gb). Use the number and then their prefix, e.g. 1MB for 1 megabyte or 500KB for 500 kilobytes. Make sure to use the letters as you see in the help output, as using lowercase letters or trying to abbreviate them (e.g. "k", "m", "g", "kb", "mb" or "gb") will not work, as that won't be parsed.

---

This should be all that's needed for most users, however, there are also some more advanced features:

- For priority (`-P`), the default is 0. The highest is 30000 and the lowest is -30000. For the five common priority settings, you can use these numbers:
    * Highest: 30000
     * High: 15000
     * Normal: 0
     * Low: -15000
     * Lowest: -30000

- For the download and upload buffer size, the default 150 KB up to about 500 KB should be good enough as a starting point for the most typical network traffic (home and light business usage). Larger buffer sizes may be necessary for handling high-traffic scenarios. This represents the maximum amount of data that will be sent in a given time. The default is to allow 150 KB of data to be transmitted per second at one time. This may also be equal to your download or upload rate size respectively. You can also try to set this to the x1.5 or x2 value of your global download and upload speed limit.

- For TCP and UDP limit, you can set the maximum number of active connections. By default, they are unlimited. TCP limit can be helpful in avoiding network saturation due to download utilities and p2p programs (like torrent clients). You may limit this to a value between 20-40, or whatever number you need. As for UDP traffic, that is mostly one way communication like video streaming, so limiting it would limit the streaming to X other devices.

- As for latency, start with small values like 1-10 to simulate some delay to reflect a poor connection. Unless you are testing, this is generally not needed. It is off by default.

- For packet loss simulation, anything between 1-10 percent should be good enough to reflect the most typical network congestions. This is off by default.

## Examples
> BandwidthShaper.exe --nic 15 -p chrome.exe -i 5000t -d 350 -u 50\
> BandwidthShaper.exe -n 15 -d 1MB -u 0.5MB

Because this uses the WinDivert driver on demand, the application must have administrator privileges! So make sure to run it from an admin CMD or PowerShell (if you want to manually open it from the x64 or x86 folder). The supplied executable files (`run-BandwidthShaper.exe` or `run-BandwidthShaper-Hidden.exe`) should open the right executable depending on your architecture (x86 or x64). All you need to do before that is to check out the options before and use your correct NIC index for your network interface(s), as well as edit the parameters to what you need in the `params.txt` file.

If you do not always want to open an elevated command prompt and manually execute the app with its flags, then it's best to set your preferred parameters in the `params.txt` file and use `run-BandwidthShaper.exe` or `run-BandwidthShaper-Hidden.exe` (you can rename these executable files). Remember: make sure to change the NIC's index number to be valid, yours will most likely need to be different from mine!

## Issues
- **I want to use this for ARM64:** This needs a WinDivert driver for ARM64, but there is no official compiled and signed version. You will either have to compile the driver yourself, or [use what was compiled by sj6219](https://github.com/sj6219/Divert/releases/tag/ARM64). Download that and copy only the `WinDivert.dll` and `WinDivert64.sys` files to the application's *arm64* folder. Because that driver has no certificate, you have to run Windows in testsign mode with the command (as admin): `Bcdedit.exe -set TESTSIGNING ON` - then restart your computer.

- **Invalid digital signature error message for the "WinDivert64.sys" or "WinDivert32.sys" file:** This may happen when running on an unsupported Windows operating system, such as Windows 7. In this case the driver can only be loaded if you disable "driver signature enforcement" in Windows. To do this, with Windows 7, you can restart the computer and keep pressing F8 until the advanced boot options menu gets displayed. Then choose "Disable driver signature enforcement". Obviously this is not recommended or a safe practice, but it's the only way to get it working on an unsupported OS. Due to security, Windows will not load the needed driver and thus no traffic shaping can take place. For a more permanent solution, you can test [sign the driver](https://reqrypt.org/windivert-faq.html#q3) yourself. [Click here](https://www.richud.com/wiki/Windows_7_Install_Unsigned_Drivers_CAT_fix) for another example.

- **I want to limit the download speed to only affect file downloads:** Your global download limit will be the overall max bandwidth available and that will be shared between all the file downloads and your network applications like a browser. This is when you should also set the TCP limit option with a reasonable number (not too low, not too high). That will slow down your current download speed for the bigger files, while you also reserve bandwidth for your other applications.

- **This does not seem to limit the speed at all:** I tested this on multiple Windows machines, and based on that limited testing, the download and upload throttling should work, even if it's not the latest Windows. Make sure that you're using the correct NIC's index number! If you did not change the default number in the batch file, this can happen, as that number may need to be different based on your hardware. In fact, due to how the `params.txt` is configured, you need to comment out the `--list-nics` line for it to work. Also try to restart the program one or two times - safely exit it with "q", then try again (something may got stuck or not applied properly).

---

## Background Info
Why was this made? The reason being is that most apps that serve this purpose can be rather complex (with many extra features) and they are usually commercial in Windows, such as [NetLimiter](https://www.netlimiter.com), [NetBalancer](https://netbalancer.com) or [SoftPerfect Bandwidth Manager](https://www.softperfect.com/products/bandwidth). At best, you can use [TMeter](http://www.tmeter.ru/en) as a free option. None of these were really appealing to me for simple bandwidth throttling (and I had no other extra need!). Now, if you ever had to use an ADSL/VDSL connection, you will know how much the upload saturation sucks, even with a smaller file. Downloading a larger file can also lead to network saturation. When this happens, browsing a website simply becomes a nightmare, as if you had a very poor connection. However, a little limit on both the download and upload speed will fix this issue. So I needed the most lightweight and portable option to throttle my download and upload speed, I did not need much else. I couldn't be bothered with router or firewall shenanigans, and a quick "on or off" via a simple tool was what I required.

Therefore, this app is only useful if you want to limit the bandwidth, either globally or for certain processes - and you really don't want much more than that. If you want other network-related features, like filtering, traffic monitoring, packet logging, quotas, predefined rules or policies, priorities per process/app, predefined break periods with alternate rate limits or no throttling, etc., then this is not the networking tool for that. For those extra features, some of the earlier mentioned apps are going to do a much better job (the downside is that they are commercial, but hey, something for something!). Of course, if that does not suit you, you're always free to fork the source code and expand on this as you'd like, you may even add a GUI! Feel free to do with it as you want (although mentioning me in the credits would be a nice gesture).

**Note:** It should go without saying, but this tool is not meant to limit the bandwidth of other computers in a network. Most likely your computer does not act as a router (gateway machine), so you will not be able to see the traffic of other users in a typical home, office or work environment. Assuming you're in a sys admin role, you're much better off using a router or firewall with pfSense or similar that has traffic shaping support or QoS, or running a transparent proxy like Squid. This small tool is for very simple use cases only. Always choose the right tool for the required job.

## Supplementary apps
This is a very simple app, but it can still be useful if you have a "X GB per month limit", although this tool does not keep track of the used bandwidth and thus you also can't set quotas (e.g. "limit speed more severely after Y GB or MB has been used"). For bandwidth usage, you may use [TrafficMonitor](https://github.com/zhongyang219/TrafficMonitor).

And if you want to preserve as much bandwidth as possible, and wish to block things like Windows background processes (Windows Update, etc.) eating up your precious bandwidth, then you would need to use an additional firewall, such as [TinyWall](https://tinywall.pados.hu/download.php) or [simplewall](https://github.com/henrypp/simplewall) and only allow trusted processes or apps to run or use your network.

For a more "all-in-one" approach, [Fort Firewall](https://github.com/tnodir/fort) is your best bet, which can also speed limit apps, making this tool unnecessary. However, when you do not need all those advanced features and only want a quick bandwidth throttling "here and now", then this tool may still have its use.

If you want to have a cleaner taskbar (to hide the CMD window), you can use [Trayy](https://github.com/alirezagsm/Trayy) for that.
