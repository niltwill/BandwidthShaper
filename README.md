# BandwidthShaper

[![Build Status](https://github.com/niltwill/BandwidthShaper/actions/workflows/main.yml/badge.svg)](https://github.com/niltwill/BandwidthShaper/actions)

## Description
This is a small, portable tool to limit bandwidth in Windows. Available for both 32-bit and 64-bit systems.

### License and Compatibility Notice
This application uses [WinDivert](https://reqrypt.org/windivert.html) to accomplish network traffic shaping. WinDivert is licensed under the GNU Lesser General Public License v3 (LGPL v3). You can find the full license text [here](https://github.com/basil00/WinDivert/blob/master/LICENSE).

WinDivert itself should support the most recent Windows operating systems, starting from Windows Vista and Windows Server 2008. It does not support older Windows versions like Windows XP. For that, you can use [Traffic Shaper XP](https://www.majorgeeks.com/files/details/traffic_shaper_xp.html) instead.

## Why bother?

You may ask: why would you ever need to use bandwidth throttling, anyway? Well, maybe you're in a good location where you don't ever actually need to do so. Indeed, most users never suffer when unlimited fiber/5G lets you go with "full blast" mode without feeling the consequences, but this is not always the case everywhere.

Consider the following scenarios:

* **Data caps / metered connections:** Mobile hotspots, capped home plans, or roaming where you don't want one background sync (OneDrive, Steam updates, Windows Update, etc.) to burn through your monthly allowance. Per-process quotas (e.g., "Chrome gets 500MB/day download quota") prevent surprises.
* **Scheduling**: You can run heavy downloads/uploads only during off-peak hours (cheaper electricity, less interference with work/gaming/family streaming). Or restrict weekdays vs. weekends as required.
* **Per-process granularity:** Not just stick to global caps, but decide which app gets how much DL and UL max, while others run unrestricted. Crucial when one process (torrent client, game patcher, video encoder) hogs the pipe (and it has no speed limit option).
* **Asymmetric connections (ADSL/VDSL/cable):** Upload saturation is brutal here, even a modest 5-10 Mbps upload (think of a YouTube 1080p stream, a large file backup, or cloud sync) can spike latency to 500-1000ms+ because the ACK packets for downloads get queued behind uploads. This means that browsing feels like dial-up (pages timeout, media content buffers forever). Throttling upload to ~80-90% of line rate leaves headroom for interactive traffic. Same for heavy downloads overwhelming buffers on the ISP side.

These are common use cases for many on non-gigabit links or capped plans.

## Two Editions

BandwidthShaper comes in two editions now: GUI and CLI. Previously, only the CLI application existed, but with the GUI, it's a lot more user-friendly. No installation required, just extract to a suitable location and run with administrator privileges.

### GUI version

![Screenshot of the GUI app with a sticky process](bandwidthshaper-gui.jpg)

The GUI app should be pretty self-explanatory and easy to use, but here's a little help to get started:

* Run `BandwidthShaper.exe` as Administrator
* Go to **View** -> **Options** and select your network interface(s)
* Set your desired download/upload limits
* Click **Start** to begin throttling
* Monitor traffic in the process list
* Double-click any cell to set limits, quotas, or schedules
* Right-click processes for available options

There's also a feature called "sticky processes". These remain in the list even when not running, which can be useful for persistent rules (e.g., always limit a browser's traffic).

### CLI version

The CLI version has the following options available:

```
Usage: BandwidthShaper [OPTIONS]
Options:
  -C, --config <path>                           Load configuration from INI-style file (overrides CLI arguments)
  -l, --lang <en|...>                           Set interface language (default: en)
                                                  Available languages: en, hu
  -P, --priority <NUM>                          Set WinDivert priority (default: 0, range: -30000 to 30000)
  -p, --process <process1,process2,...>         List of process names to monitor (comma-separated)
  -z, --pid <pidnum1,pidnum2,...>               List of PIDs to monitor (comma-separated)
  -c, --rule <process|PID> <DL_RATE> <UL_RATE>  Set custom rate limit(s) for a process or PID
  -S, --stop-at <process|PID> <QI> <QO>         Set inbound/outbound data quota for a process or PID
                                                  Quota values accept units: b, KB, MB, GB (e.g. 500MB)
  -T, --schedule [HHMM-HHMM][~<days>]           Restrict preceding -p/-z/-c/-S to a time/day window
                                                  Days: 1=Mon..7=Sun; ranges (1-5) and lists (1,3,5) OK
                                                  Examples: 0800-1800~1-5  2200-0600~6,7
  -Q, --quota-check-interval <ms>               How often to check quotas/schedules (default: 1000ms)
  -I, --stats-interval <ms>                     How often to print statistics (default: 5000ms, requires -s)
  -i, --process-update-interval <NUM>[p|t][,c]  Packet/time threshold for PID refresh + optional cooldown
  -a, --disable-after <RATE>[KB|MB|GB]          Disable internet after reaching data cap (0 = no cap)
  -d, --download <RATE>[b|Kb|KB|Mb|MB|Gb|GB]    Download speed limit per second (default unit: KB)
  -u, --upload <RATE>[b|Kb|KB|Mb|MB|Gb|GB]      Upload speed limit per second (default unit: KB)
  -D, --download-buffer <bytes>                 Max download buffer size in bytes (default: 150000)
  -U, --upload-buffer <bytes>                   Max upload buffer size in bytes (default: 150000)
  -t, --tcp-limit <NUM>                         Max active TCP connections (0 = unlimited)
  -r, --udp-limit <NUM>                         Max UDP packets/sec (0 = unlimited)
  -b, --burst <RATE>[b|Kb|KB|Mb|MB|Gb|GB]       Burst size override (0 = use buffer size)
  -L, --latency <ms>                            Simulated latency in ms (0 = none)
  -m, --packet-loss <float>                     Simulated packet loss % (0.00 = none)
  -n, --nic <index>[:<DL>:<UL>][,...]           NIC index(es) to throttle; optional per-NIC rates
  -A, --list-nics                               List all available network interfaces
  -s, --statistics                              Enable periodic statistics output
  -q, --quiet                                   Suppress most console messages
  -v, --version                                 Display version and exit
  -h, --help                                    Display this help and exit
```

You can also use the supplied **BandwidthShaper.ini** configuration file so that you don't need to always use parameters.

Some examples below...

```
# Global limit on interface 15
BandwidthShaper.exe -n 15 -d 1MB -u 500KB

# Multiple interfaces with different rates
BandwidthShaper.exe -n 14:2MB:1MB,15:1MB:500KB

# Limit specific processes
BandwidthShaper.exe -n 15 -p chrome.exe,firefox.exe -d 500KB -u 100KB

# Different limits per process
BandwidthShaper.exe -n 15 -c "chrome.exe 1MB 200KB" -c "firefox.exe 500KB 100KB"

# Target specific PIDs
BandwidthShaper.exe -n 15 -z 1234,5678 -d 500KB -u 100KB

# Stop Chrome after 1GB download or 500MB upload
BandwidthShaper.exe -n 15 -S chrome.exe 1GB 500MB

# Quota with rate limits
BandwidthShaper.exe -n 15 -c "chrome.exe 1MB 200KB" -S chrome.exe 1GB 500MB

# Weekdays 8am-6pm only
BandwidthShaper.exe -n 15 -p chrome.exe -d 500KB -T 0800-1800~1-5

# Weekend overnight only
BandwidthShaper.exe -n 15 -c "steam.exe 2MB 1MB" -T 2200-0600~6,7

# NIC 14: 2MB down, 1MB up
# NIC 15: 1MB down, 500KB up
BandwidthShaper.exe -n 14:2MB:1MB,15:1MB:500KB

# Block uploads for chrome.exe
BandwidthShaper.exe -n <your index> -c "chrome.exe 1MB -1"

# Update every 1000 packets
BandwidthShaper.exe -n <your index> -p chrome.exe -i 1000p

# Update every 5 seconds
BandwidthShaper.exe -n <your index> -p chrome.exe -i 5000t
```

Schedules can be applied to specific processes in two ways. One is to use command-line arguments, where the schedule applies to the immediately preceding process target:

```
# Apply schedule to a specific process rule
BandwidthShaper.exe -n <your index> -c "chrome.exe 5MB 2MB" -T "0800-1800~1-5"

# Apply schedule to a stop-at quota rule
BandwidthShaper.exe -n <your index> -S "firefox.exe 1GB 500MB" -T "2200-0600~6,7"

# Apply schedule to a process list
BandwidthShaper.exe -n <your index> -p "chrome.exe,firefox.exe" -T "0900-1700~1-5"

# Apply schedule to specific PIDs
BandwidthShaper.exe -n <your index> -z 1234,5678 -T "1800-2200~1-5"
```

The second method is using the configuration file, in this case, schedules are applied to the most recently defined rule:

```
# Rule for Chrome with schedule
rule = chrome.exe 5MB 2MB
schedule = 0800-1800~1-5    ; Only applies to Chrome, weekdays 8am-6pm

# Rule for Firefox with different schedule  
rule = firefox.exe 3MB 1MB
schedule = 2200-0600~6,7    ; Only applies to Firefox, weekends overnight

# Stop-at quota with schedule
stop-at = edge.exe 500MB 250MB
schedule = 0900-1700~1-5     ; Only applies to Edge, business hours

# Process list with schedule
process = notepad.exe,calc.exe
schedule = 1800-2200~1-5     ; Only applies to Notepad and Calculator, evenings

# This schedule would apply to any previously defined rule that doesn't have its own
schedule = 0000-2359~1-7     ; Global fallback schedule
```

There has to be a --rule, --stop-at, --process, or --pid before the --schedule. If yes, it applies the schedule to that specific rule. If not, it becomes a global schedule that applies to all throttled traffic. So you have to remember, that the order matters here: the schedule must come after the process/rule it applies to, not before. Each process target can have its own unique schedule. If a schedule appears before any process targets, it applies to all throttled traffic.

## Translation

If you wish to add new language: use the English text files from the [language](https://github.com/niltwill/BandwidthShaper/tree/main/src/language) folder. It's simple plain text translation for three files - no need to know the keys, just edit the strings between the quotation marks. The multiline strings can spawn as many lines as you need, but make sure it closes with an ending quotation mark, followed by a comma. Once the translation is finished, open an issue or pull request. Note that this can't be easily tested, as the inclusion requires recompilation. This was a design decision - so that the user can't simply ruin the strings by editing pre-existing files or by removing/misplacing such files.

To test it, you need to compile the program yourself and include the changes in three localization-related files (`localization_api.c`, `localization_ids.h`, `localization_data.c`). Otherwise, expect some back and forth feedback to iron this out. The string length can be a problem in certain languages (in the GUI or the default CLI window size - the English strings fit without newlines, a translation may not - though in the CLI, it's not that big of an issue).

## Issues

- **"Saved NIC not found" warning:** The network adapter got changed or disabled. Go to Options and reselect your NICs.

- **No throttling happening:** Check if you use the correct NIC index (use --list-nics) in the CLI and the correct NIC in the GUI app. Make sure you have admin privileges. There should be no conflicting QoS or router throttling - if there are, either use those or this app, but not both. Also check that the WinDivert service isn't stuck.

- **My internet connection stopped working:** The throttler may get blocked by a third party firewall or other security software automatically (if it's configured to only allow whitelisted processes or apps), which means your internet will no longer work. You have to whitelist this throttler or set your firewall/security software to learning mode, and allow it that way when it notifies you. If you want to test if this is the cause, try to temporarily disable your firewall or security software and see if that makes it work.

- **Throttling doesn't seem to work:** Certain apps may not play well with the throttling itself. They may reject the connection quickly or immediately. Sometimes this means you can't throttle those apps, if they have detection algorithm(s) for this intentionally.

- **Invalid digital signature error message for the "WinDivert64.sys" or "WinDivert32.sys" file:** This may happen when running on an unsupported Windows operating system, such as Windows 7. In this case the driver can only be loaded if you disable "driver signature enforcement" in Windows. To do this, with Windows 7, you can restart the computer and keep pressing F8 until the advanced boot options menu gets displayed. Then choose "Disable driver signature enforcement". Obviously this is not recommended or a safe practice, but it's the only way to get it working on an unsupported OS. Due to security, Windows will not load the needed driver and thus no traffic shaping can take place. For a more permanent solution, you can test [sign the driver](https://reqrypt.org/windivert-faq.html#q3) yourself. [Click here](https://www.richud.com/wiki/Windows_7_Install_Unsigned_Drivers_CAT_fix) for another example.

- **I want to limit the download speed to only affect file downloads:** Your global download limit will be the overall max bandwidth available and that will be shared between all the file downloads and your network applications like a browser. This is when you should also set the TCP limit option with a reasonable number (not too low, not too high). That will slow down your current download speed for the bigger files, while you also reserve bandwidth for your other applications.

## WinDivert Cleanup

If the shaper exits uncleanly, the driver may remain loaded, so either reboot to unload the driver or clean it up manually with these commands in a CMD or PowerShell window:

```
sc stop WinDivert
sc delete WinDivert
sc query WinDivert
```

---

## Background Info
Why was this made? The reason being is that most apps that serve this purpose can be rather complex (with many extra features) and they are usually commercial in Windows, such as [NetLimiter](https://www.netlimiter.com), [NetBalancer](https://netbalancer.com) or [SoftPerfect Bandwidth Manager](https://www.softperfect.com/products/bandwidth). At best, you can use [TMeter](http://www.tmeter.ru/en) as a free option. None of these were really appealing to me for simple bandwidth throttling (and I had no other extra need!). Now, if you ever had to use an ADSL/VDSL connection, you will know how much the upload saturation sucks, even with a smaller file. Downloading a larger file can also lead to network saturation. When this happens, browsing a website simply becomes a nightmare, as if you had a very poor connection.

**Note:** It should go without saying, but this tool is not meant to limit the bandwidth of other computers in a network. Most likely your computer does not act as a router (gateway machine), so you will not be able to see the traffic of other users in a typical home, office or work environment. Assuming you're in a sys admin role, you're much better off using a router or firewall with pfSense or similar that has traffic shaping support or QoS, or running a transparent proxy like Squid. This small tool is for very simple use cases only. Always choose the right tool for the required job.

## What about Feature X or Y?

This app was intended to be a *simple, free replacement* for software like NetLimiter. If someone needs other advanced features, they can use those commercial applications instead. I'm personally not going to add (overly) complex features here. More code means more potential for bugs and harder maintenance. I aim to avoid the classic scope screep that many solo devs can fall into with unchecked ambition - so each feature is carefully considered before implementation.

If you take a look in the open-source and free software space, a lot of apps may only implement the most practical features (or a subset of the most used ones), and leave the rest to the paid alternatives, where the devs get paid to implement those and have the incentive to keep polishing it for the (usually enterprise) users who request it. Those devs may make their living from that singular software or other software projects - so of course they are incentivized to improve upon them. For me, there are other things to do in my life than to solely polish this for years/decades to come. It's made on the side in my free time, no strings attached.

While it's easy to look at NetLimiter's feature list and feel like a need to match it, but that's a product that's been commercially developed for years with paying customers funding each addition. This is not a competition for market share - commercial software may have to compete with each other, while I don't. I made mine in weeks for my personal needs, which then got slowly iterated and polished over months. Indeed, this was made to satisfy the core usage of a bandwidth shaper first and foremost: to see what's using your bandwidth, put a cap on it, set it and forget it. That's what 95% of people actually need. The remaining 5% who need per-user limits, deep packet inspection, protocol-level filtering, more advanced statistics or enterprise policy management have both the budget and the justification to pay for a commercial tool. This also creates a nice segregation in our usage model: use the commercial apps for the greater requirements, and this free app for the simple use cases.

### Features that will not be included

There were two potential features that got scrapped right at the planning phase, so don't request these:

**1.** A service implementation for Windows. For users who want to make this a service, there's already a nifty tool for that called [Servy](https://github.com/aelassas/servy). While in some cases, it could make sense to have to apply bandwidth throttling constantly, but not everyone needs that. I personally wouldn't want to increase the complexity by having to maintain Windows service-related code (service handlers, SCM interaction, Session 0 isolation). Servy, NSSM, and similar tools exist so application developers don't have to solve that complex problem (with all that it entails). A user who needs it as a service is probably technical enough to use one of those tools (or their own scripts/workarounds).

**2.** Bandwidth usage limitation *per user*. Since only one user is logged in at a time usually, this addition does not make much sense. This shaper operates at the network driver level, filtering by PID. To throttle by user, it'd need to enumerate which PIDs belong to which user, then group those PIDs under a user-level rule. That enumeration would need to happen continuously, since PIDs come and go, and this is already doing per-process tracking. All things considered, this wouldn't give us many benefits, and it'd be merely an aggregation layer on top of what already exists. The (special) username adds an indirection, and you'd still end up throttling the same processes, just discovered in a different way. The per-process view already gives us everything meaningful that per-user would give. The SYSTEM user angle sounds appealing, but it would be frustratingly coarse in practice, since we could be throttling dozens of unrelated system services alongside the one we want (a single svchost.exe PID hosts multiple services). For Windows Update specifically, you can use the Delivery Optimization settings.
