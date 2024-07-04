# Resources for Windows Security Research

**Compiled by !cpuid from the OffSec Discord server!**

Here is a list of curated resources that cover various aspects of Windows security research:

## Recommended Blogs

* [Jan Vojtěšek's Blog](https://decoded.avast.io/janvojtesek/)
* [Matteo Malvica's Blog](https://www.matteomalvica.com/blog/)
* [Satoshi Tanda's Blog](https://tandasat.github.io/blog/)
* [Le Qi Chen's Blog](https://y3a.github.io/)
* [Marcus Hutchins' Blog](https://malwaretech.com/)
* [Tavis Ormandy's Blog](https://lock.cmpxchg8b.com/)
* [Robel Campbell's Blog](https://reverencecyber.com/blog/)
* [Connor McGarr's Blog](https://connormcgarr.github.io/)
* [Eugene Lim's Blog](https://spaceraccoon.dev/)
* [Richard Osgood's Blog](https://www.richardosgood.com/)
* [Yarden Shafir's Blog](https://medium.com/@yardenshafir2)
* [Hashim Jawad's Blog](https://ihack4falafel.github.io/)
* [Alex Plaskett's Blog](https://alexplaskett.github.io/)
* [h0mbre's Blog](https://h0mbre.github.io)
* [k0shl's Blog](https://whereisk0shl.top/)
* [DHN's Blog](https://zer0-day.pw/)
* [Project Zero's Blog](https://googleprojectzero.blogspot.com/)


## Recommended Repositories

* [Morten Schenk's GitHub](https://github.com/MortenSchenk)
* [Tavis Ormandy's GitHub](https://github.com/taviso)

## Windows Notification Facility

* [Gabriella Viala and Alex Ionescu's Repo](https://github.com/ionescu007/wnfun/tree/master)
* [WNF Chronicles by PWNed Coffee](https://pwnedcoffee.com/blog/wnf-chronicles-i-introduction/)

## Technical Deep-Dives

* [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) by Intel


### Windows Mitigation Bypasses and Analysis


#### General

* [CVE-2023-36802 MSSKSRV.sys Local Privilege Escalation](https://reverencecyber.com/cve-2023-36802-mssksrv-sys-local-privilege-escalation-poc/) by Robel Campbell
* [IRQLs Close Encounters of the Rootkit Kind](https://www.offsec.com/offsec/irqls-close-encounters/) by OffSec
* [Windows Exploitation Tricks: Trapping Virtual Memory Access](https://googleprojectzero.blogspot.com/2021/01/windows-exploitation-tricks-trapping.html) by James Forshaw
* [Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html) by James Forshaw
* [Discovery and analysis of a Windows PhoneBook Use-After-Free vulnerability (CVE-2020-1530)](https://symeonp.github.io/2020/12/08/phonebook-uaf-analysis.html) by Symeon
* [itsec stuff about fuzzing, vuln hunting and (hopefully) exploitation!](https://symeonp.github.io/) by Symeon
* [Part 19: Kernel Exploitation -> Logic bugs in Razer rzpnk.sys](https://fuzzysecurity.com/tutorials/expDev/23.html) by Fuzzy Security
* [I Got 99 Problem But a Kernel Pointer Ain't One](https://recon.cx/2013/slides/Recon2013-Alex%20Ionescu-I%20got%2099%20problems%20but%20a%20kernel%20pointer%20ain%27t%20one.pdf) by Alex Ionescu
* [Windows Code Injection: Bypassing CIG Through KnownDlls](https://www.tiraniddo.dev/2019/08/windows-code-injection-bypassing-cig.html?m=1) by Tyranid's Lair


#### Intel CET

* [Bypassing Intel CET with Counterfeit Objects](https://www.offsec.com/offsec/bypassing-intel-cet-with-counterfeit-objects/) by Matteo Malvica
* [Intel CET in Action](https://www.offsec.com/offsec/intel-cet-in-action/) by OffSec


#### Windows Defender Exploit Guard (Previously EMET)

* [eXtended Flow Guard Under The Microscope](https://www.offsec.com/offsec/extended-flow-guard/) by OffSec
* [Disarming EMET v5.0](https://www.offsec.com/vulndev/disarming-emet-v5-0/) by Matteo Memelli
* [Disarming Enhanced Mitigation Experience Toolkit (EMET)](https://www.offsec.com/vulndev/disarming-enhanced-mitigation-experience-toolkit-emet/) by Matteo Memelli
* [Bypassing Control Flow Guard in Windows 10 - Part II](https://blog.improsec.com/tech-blog/bypassing-control-flow-guard-on-windows-10-part-ii) by Morten Schenk


### Just-in-Time Compilation

> Note: Some of these blog posts are iOS-related, but since JIT is used in Windows applications, I have included them here.

* [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 1)](https://connormcgarr.github.io/type-confusion-part-1/) by Connor McGarr
* [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 2)](https://connormcgarr.github.io/type-confusion-part-2/) by Connor McGarr
* [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 3)](https://connormcgarr.github.io/type-confusion-part-3/) by Connor McGarr
* [Understanding the Risk in the Unintended Giant: JavaScript](https://www.zerodayinitiative.com/blog/2017/7/18/understanding-risk-in-the-unintended-giant-javascript) by Simon Zuckerbraun
* [Check It Out: Enforcement of Bounds Checks in Native JIT Code](https://www.zerodayinitiative.com/blog/2017/10/5/check-it-out-enforcement-of-bounds-checks-in-native-jit-code) by Simon Zuckerbraun
* [Floating-Poison Math in Chakra](https://www.zerodayinitiative.com/blog/2018/8/22/floating-poison-math-in-chakra) by Simon Zuckerbraun
* [Bypassing Mitigations by Attacking JIT Server in Microsoft Edge](https://googleprojectzero.blogspot.com/2018/05/bypassing-mitigations-by-attacking-jit.html) by Ivan Fratric
* [JITSploitation I: A JIT Bug](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-one.html) by Samuel Groß
* [JITSploitation II: Getting Read/Write](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-two.html) by Samuel Groß
* [JITSploitation III: Subverting Control Flow](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-three.html) by Samuel Groß


### Hyper-V

* [Who Contains the Containers?](https://googleprojectzero.blogspot.com/2021/04/who-contains-containers.html) by James Forshaw
* [A Dive in to Hyper-V Architecture & Vulnerabilities](https://i.blackhat.com/us-18/Wed-August-8/us-18-Joly-Bialek-A-Dive-in-to-Hyper-V-Architecture-and-Vulnerabilities.pdf) by Nicolas Joly and Joe Bialek
* [First Steps in Hyper-V Research](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/) by Microsoft
* [Fuzzing para-virtualized devices in Hyper-V](https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/) by Microsoft


### WinDbg

* [WinDbg Commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/debugger-commands)
* [WinDBG quick start tutorial](https://codemachine.com/articles/windbg_quickstart.html) by CodeMachine
* [My WinDbg Blog](https://0x4n3.github.io/windows/WinDbg)


### Fuzzing

* [Gamozo Labs' Blog](https://gamozolabs.github.io/)
* [Google Project Zero's WinAFL](https://github.com/googleprojectzero/winafl)
* [SafeBreach & Guardicore Labs' hAFL1](https://github.com/SB-GC-Labs/hAFL1)


### Presentations and Walkthroughs

* [The Info Leak Era on Software Exploitation](https://www.youtube.com/watch?v=VgWoPa8Whmc) by Fermin J. Serna
* [Windows 10 Mitigation Improvements](https://www.youtube.com/watch?v=gCu2GQd0GSE) by David Weston and Matt Miller
* [Windows 10 Segment Heap Internals](https://www.youtube.com/watch?v=hetZx78SQ_A) by Mark Vincent Yason
* [Taking Windows 10 Kernel Exploitation to the next level](https://www.youtube.com/watch?v=Gu_5kkErQ6Y) by Morten Schenk
* [PowerShell as an attack platform](https://www.youtube.com/watch?v=MOab2Icpecc) by Morten Schenk
* [Data-Only Pwning Microsoft Windows Kernel](https://www.youtube.com/watch?v=FxZoAupttMI) by Nikita Tarakanov
* [Advanced Heap Manipulation in Windows 8](https://www.youtube.com/watch?v=0lURSnDOPfQ) by Zhenhua Liu
* [Demystifying Windows Kernel Exploitation by Abusing GDI Objects](https://www.youtube.com/watch?v=2chDv_wTymc) by Saif El Sherei
* [Exploiting Hardcore Pool Corruptions in MS Windows Kernel](https://www.youtube.com/watch?v=2yuza8PRGVQ) by Nikita Tarakanov
* [Windows kernel exploitation techniques](https://www.youtube.com/watch?v=f8hTwFpRphU) by Adrien Garin
* [Practical Windows Kernel Exploitation](https://www.youtube.com/watch?v=hUCmV7uT29I) by Spencer McIntyre
* [Over The Edge: Pwning The Windows Kernel](https://www.youtube.com/watch?v=0tFmqSbWSZE) by Rancho Han
* [Theres a party at ring0](https://www.youtube.com/watch?v=BCavCemZPoI) by Tavis Ormandy and Julien Tinnes
* [Extreme Privilege Escalation On Windows 8 UEFI Systems](https://www.youtube.com/watch?v=Qj_YCpoct3k) by Corey Kallenberg, Xeno Kovah, John Butterworth, and Sam Cornwell
* [Windows privilege escalation using 3rd party services](https://www.youtube.com/watch?v=nRVbYt9LKXk) by Kacper Szurek
* [Practical Windows Privilege Escalation](https://www.youtube.com/watch?v=PC_iMqiuIRQ) by Andrew Smith
* [Windows Kernel Vulnerability Research and Exploitation](https://www.youtube.com/watch?v=aRZ5Wi-NWXs) by Gilad Bakas
* [Hackingz Ze Komputerz - Exploiting CAPCOM.SYS Part 1](https://www.youtube.com/watch?v=pJZjWXxUEl4) by OJ Reeves
* [Hackingz Ze Komputerz - Exploiting CAPCOM.SYS Part 2](https://www.youtube.com/watch?v=UGWqq5kTiso) by OJ Reeves
* [ROP mitigations and Control Flow Guard - the end of code reuse attacks?](https://www.youtube.com/watch?v=pqU9jsCmlYA) by Matthias Ganz 
* [Building Windows Kernel Fuzzer](https://www.youtube.com/watch?v=mpXQvto4Vy4) by Jaanus Kääp


## Books

* [Windows Kernel Programming](https://www.amazon.com/Windows-Kernel-Programming-Pavel-Yosifovich/dp/1977593372) by Pavel Yosifovich
* [Windows Internals, Part 1: System architecture, processes, threads, memory management, and more, 7th Edition](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188) by Pavel Yosifovich, Mark E. Russinovich, Alex Ionescu, David A. Solomon
* [Windows Internals, Part 2, 7th Edition](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409) by Andrea Allievi, Mark E. Russinovich, Alex Ionescu, David A. Solomon
* [What Makes it Page? The Windows 7 (x64) Virtual Memory Manager](https://www.amazon.com/What-Makes-Page-Windows-Virtual/dp/1479114294) by Enrico Martignetti


## Courses

* [EXP-301](https://www.offsec.com/documentation/EXP301-syllabus.pdf) by OffSec
* [EXP-401](https://www.offensive-security.com/awe/EXP401_syllabus.pdf) by OffSec
* [Windows Internal Architecture](https://codemachine.com/trainings/winint.html) by CodeMachine
* [Windows Malware Techniques](https://codemachine.com/trainings/winmal.html) by CodeMachine
* [Windows Kernel Internals](https://codemachine.com/trainings/kerint.html) by CodeMachine
* [Windows Kernel Rootkits](https://codemachine.com/trainings/kerrkt.html) by CodeMachine
* [SEC760: Advanced Exploit Development for Penetration Testers](https://www.sans.org/cyber-security-courses/advanced-exploit-development-penetration-testers/) by SANS
* [Corelan Advanced - Heap Exploitation](https://www.corelan-training.com/index.php/training/advanced/) by Corelan
* [Corelan Bootcamp - Stack Exploitation](https://www.corelan-training.com/index.php/training/bootcamp/) by Corelan


## Advisories

The best way to get better at vulnerability research is to practice. As a result, I have compiled a list of some advisories Google's Project Zero has produced that may help in facilitating what real bugs look like in Windows.


### AFD

* [Windows Kernel pool-based out-of-bound reads due to bugs in the implementation of bind() in afd.sys and tcpip.sys](https://bugs.chromium.org/p/project-zero/issues/detail?id=1127)


### Avalon

* [Microsoft Windows Presentation Foundation memory disclosure via uninitialized transient array](https://bugs.chromium.org/p/project-zero/issues/detail?id=277)


### Defender

* [Windows Defender: Controlled Folder Bypass through UNC Path](https://bugs.chromium.org/p/project-zero/issues/detail?id=1418)


### DirectWrite

* [Microsoft DirectWrite / AFDKO stack corruption in OpenType font handling due to out-of-bounds cubeStackDepth](https://bugs.chromium.org/p/project-zero/issues/detail?id=1829)
* [Microsoft DirectWrite / AFDKO stack corruption in OpenType font handling due to negative cubeStackDepth](https://bugs.chromium.org/p/project-zero/issues/detail?id=1830)
* [Microsoft DirectWrite / AFDKO stack corruption in OpenType font handling due to negative nAxes](https://bugs.chromium.org/p/project-zero/issues/detail?id=1831)
* [Microsoft DirectWrite / AFDKO stack-based buffer overflow in do_set_weight_vector_cube for large nAxes](https://bugs.chromium.org/p/project-zero/issues/detail?id=1832)
* [Microsoft DirectWrite / AFDKO use of uninitialized memory while freeing resources in var_loadavar](https://bugs.chromium.org/p/project-zero/issues/detail?id=1833)
* [Microsoft DirectWrite / AFDKO interpreter stack underflow in OpenType font handling due to missing CHKUFLOW](https://bugs.chromium.org/p/project-zero/issues/detail?id=1834)
* [Microsoft DirectWrite / AFDKO stack corruption in OpenType font handling due to incorrect handling of blendArray](https://bugs.chromium.org/p/project-zero/issues/detail?id=1835)
* [Microsoft DirectWrite / AFDKO heap-based buffer overflow in OpenType font handling in readEncoding](https://bugs.chromium.org/p/project-zero/issues/detail?id=1836)
* [Microsoft DirectWrite / AFDKO heap-based buffer overflow in OpenType font handling in readFDSelect](https://bugs.chromium.org/p/project-zero/issues/detail?id=1837)
* [Microsoft DirectWrite / AFDKO heap-based buffer overflow in OpenType font handling in readCharset](https://bugs.chromium.org/p/project-zero/issues/detail?id=1838)
* [Microsoft DirectWrite / AFDKO heap-based buffer overflow due to integer overflow in readTTCDirectory](https://bugs.chromium.org/p/project-zero/issues/detail?id=1839)
* [Microsoft DirectWrite / AFDKO heap-based out-of-bounds read/write in OpenType font handling due to unbounded iFD](https://bugs.chromium.org/p/project-zero/issues/detail?id=1840)
* [Microsoft DirectWrite / AFDKO heap-based buffer overflow in OpenType font handling in readStrings](https://bugs.chromium.org/p/project-zero/issues/detail?id=1841)
* [Microsoft DirectWrite / AFDKO stack corruption in OpenType font handling while processing CFF blend DICT operator](https://bugs.chromium.org/p/project-zero/issues/detail?id=1842)
* [Microsoft DirectWrite / AFDKO out-of-bounds read in OpenType font handling due to undefined FontName index](https://bugs.chromium.org/p/project-zero/issues/detail?id=1843)
* [Microsoft DirectWrite / AFDKO multiple bugs in OpenType font handling related to the "post" table](https://bugs.chromium.org/p/project-zero/issues/detail?id=1844)
* [Microsoft DirectWrite / AFDKO NULL pointer dereferences in OpenType font handling while accessing empty dynarrays](https://bugs.chromium.org/p/project-zero/issues/detail?id=1845)
* [Microsoft DirectWrite / AFDKO heap-based out-of-bounds read/write in OpenType font handling due to empty ROS strings](https://bugs.chromium.org/p/project-zero/issues/detail?id=1846)
* [Microsoft DirectWrite / AFDKO insufficient integer overflow check in dnaGrow](https://bugs.chromium.org/p/project-zero/issues/detail?id=1847)
* [Microsoft DirectWrite / AFDKO read of uninitialized BuildCharArray memory in OpenType font handling](https://bugs.chromium.org/p/project-zero/issues/detail?id=1848)
* [Microsoft DirectWrite invalid read in SplicePixel while processing OTF fonts](https://bugs.chromium.org/p/project-zero/issues/detail?id=1875)
* [Microsoft DirectWrite out-of-bounds read in sfac_GetSbitBitmap while processing TTF fonts](https://bugs.chromium.org/p/project-zero/issues/detail?id=1878)
* [Microsoft DirectWrite heap-based buffer overflow in fsg_ExecuteGlyph while processing variable TTF fonts](https://bugs.chromium.org/p/project-zero/issues/detail?id=2123)


### DotNet

* [Windows: ManagementObject Arbitrary .NET Serialization RCE](https://bugs.chromium.org/p/project-zero/issues/detail?id=1081)
* [.NET Partial-Trust bypass via browser command-line injection in System.Windows.Forms.Help](https://bugs.chromium.org/p/project-zero/issues/detail?id=481)


### Microsoft Edge

* [Microsoft Edge and IE: Type confusion in HandleColumnBreakOnColumnSpanningElement](https://bugs.chromium.org/p/project-zero/issues/detail?id=1011)
* [Microsoft Edge: Type confusion in CssParser::RecordProperty](https://bugs.chromium.org/p/project-zero/issues/detail?id=1254)
* [Microsoft Edge: textarea.defaultValue memory disclosure](https://bugs.chromium.org/p/project-zero/issues/detail?id=1255)
* [Microsoft Edge: Out-of-bounds read in CInputDateTimeScrollerElement::_SelectValueInternal](https://bugs.chromium.org/p/project-zero/issues/detail?id=1264)
* [Microsoft Edge: ACG bypass using DuplicateHandle](https://bugs.chromium.org/p/project-zero/issues/detail?id=1299)
* [Microsoft Edge: Memory corruption with Object.setPrototypeOf](https://bugs.chromium.org/p/project-zero/issues/detail?id=1339)
* [Microsoft Edge: ACG bypass using UnmapViewOfFile](https://bugs.chromium.org/p/project-zero/issues/detail?id=1435)
* [Microsoft Edge: ACG bypass with OpenProcess()](https://bugs.chromium.org/p/project-zero/issues/detail?id=1552)
* [Microsoft Edge: Chakra: Bugs in InitializeNumberFormat and InitializeDateTimeFormat](https://bugs.chromium.org/p/project-zero/issues/detail?id=1582)
* [Windows: Edge/IE Isolated Private Namespace Insecure Boundary Descriptor EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=878)
* [Windows: Edge/IE Isolated Private Namespace Insecure DACL EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=879)


### Fontsub

* [Microsoft Font Subsetting DLL returning a dangling pointer via MergeFontPackage](https://bugs.chromium.org/p/project-zero/issues/detail?id=1862)
* [Microsoft Font Subsetting DLL heap-based out-of-bounds read in MergeFonts](https://bugs.chromium.org/p/project-zero/issues/detail?id=1863)
* [Microsoft Font Subsetting DLL heap-based out-of-bounds read in GetGlyphIdx](https://bugs.chromium.org/p/project-zero/issues/detail?id=1864)
* [Microsoft Font Subsetting DLL double free in MergeFormat12Cmap / MakeFormat12MergedGlyphList](https://bugs.chromium.org/p/project-zero/issues/detail?id=1865)
* [Microsoft Font Subsetting DLL heap corruption in ComputeFormat4CmapData](https://bugs.chromium.org/p/project-zero/issues/detail?id=1866)
* [Microsoft Font Subsetting DLL heap corruption in FixSbitSubTables](https://bugs.chromium.org/p/project-zero/issues/detail?id=1867)
* [Microsoft Font Subsetting DLL heap corruption in ReadTableIntoStructure](https://bugs.chromium.org/p/project-zero/issues/detail?id=1868)
* [Microsoft Font Subsetting DLL heap corruption in ReadAllocFormat12CharGlyphMapList](https://bugs.chromium.org/p/project-zero/issues/detail?id=1869)
* [Microsoft Font Subsetting DLL heap-based out-of-bounds read in WriteTableFromStructure](https://bugs.chromium.org/p/project-zero/issues/detail?id=1870)
* [Microsoft Font Subsetting DLL heap corruption in MakeFormat12MergedGlyphList](https://bugs.chromium.org/p/project-zero/issues/detail?id=1871)
* [Microsoft Font Subsetting DLL heap-based out-of-bounds read in FixSbitSubTableFormat1](https://bugs.chromium.org/p/project-zero/issues/detail?id=1872)


### GDI32.dll

* [Windows gdi32.dll multiple issues in the EMF CREATECOLORSPACEW record handling](https://bugs.chromium.org/p/project-zero/issues/detail?id=722)
* [Windows gdi32.dll multiple issues in the EMF COMMENT_MULTIFORMATS record handling](https://bugs.chromium.org/p/project-zero/issues/detail?id=729)
* [Windows gdi32.dll heap-based buffer overflow in ExtEscape() triggerable via EMR_EXTESCAPE EMF record](https://bugs.chromium.org/p/project-zero/issues/detail?id=731)
* [Windows gdi32.dll heap-based out-of-bounds reads / memory disclosure in multiple DIB-related EMF record handlers](https://bugs.chromium.org/p/project-zero/issues/detail?id=757)
* [Windows gdi32.dll heap-based out-of-bounds reads / memory disclosure in EMR_SETDIBITSTODEVICE and possibly other records](https://bugs.chromium.org/p/project-zero/issues/detail?id=992)


### GDI+

* [Microsoft GDI+ out-of-bounds write due to invalid pointer arithmetic in DecodeCompressedRLEBitmap](https://bugs.chromium.org/p/project-zero/issues/detail?id=824)
* [Microsoft GDI+ rendering of uninitialized heap bytes as pixels when handling malformed RLE-compressed bitmaps](https://bugs.chromium.org/p/project-zero/issues/detail?id=825)
* [Microsoft GDI+ out-of-bounds reads due to invalid pointer arithmetic in ValidateBitmapInfo](https://bugs.chromium.org/p/project-zero/issues/detail?id=826)
* [Microsoft GDI+ heap-based buffer overflow in the handling of EMR_EXTTEXTOUTA and EMR_POLYTEXTOUTA records](https://bugs.chromium.org/p/project-zero/issues/detail?id=828)
* [Microsoft GDI+ out-of-bounds reads in DIB palette handling in ValidateBitmapInfo](https://bugs.chromium.org/p/project-zero/issues/detail?id=829)
* [Microsoft GDI+ out-of-bounds read in gdiplus!GetRECTSForPlayback](https://bugs.chromium.org/p/project-zero/issues/detail?id=1042)


### Hyper-V

* [Hyper-V vmswitch.sys VmsMpCommonPvtHandleMulticastOids Guest to Host Kernel-Pool Overflow](https://bugs.chromium.org/p/project-zero/issues/detail?id=688)
* [Windows: Double Dereference in NtEnumerateKey Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=1599)
* [Windows: Server Silo Registry Key Symbolic Link EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2120)
* [Windows Containers: ContainerUser has Elevated Privileges](https://bugs.chromium.org/p/project-zero/issues/detail?id=2127)
* [Windows Containers: AppSilo Object Manager Root Directory EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2128)
* [Windows Containers: Host Registry Virtual Registry Provider Bypass EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2129)
* [Windows: Container Manager Service CmsRpcSrv_CreateContainer EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2149)
* [Windows: Container Manager Service CmsRpcSrv_MapVirtualDiskToContainer EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2150)
* [Windows: Container Manager Service Arbitrary Object Directory Creation EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2151)
* [Windows: Container Manager Service CmsRpcSrv_MapNamedPipeToContainer EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=2153)


### ICM32.dll

* [Microsoft Color Management Module (icm32.dll) out-of-bounds read in icm32!Fill_ushort_ELUTs_from_lut16Tag](https://bugs.chromium.org/p/project-zero/issues/detail?id=1052)
* [Microsoft Color Management Module (icm32.dll) out-of-bounds read in icm32!LHCalc3toX_Di16_Do16_Lut8_G32](https://bugs.chromium.org/p/project-zero/issues/detail?id=1054)


### Windows Kernel

* [Windows Kernel ATMFD.DLL DoS via unlimited CharString program execution](https://bugs.chromium.org/p/project-zero/issues/detail?id=169)
* [Windows Kernel ATMFD.DLL out-of-bounds reads from the input CharString stream](https://bugs.chromium.org/p/project-zero/issues/detail?id=174)
* [Windows Kernel ATMFD.DLL off-by-x oob reads/writes relative to the operand stack](https://bugs.chromium.org/p/project-zero/issues/detail?id=175)
* [Windows Kernel ATMFD.DLL kernel pool memory disclosure via uninitialized transient array](https://bugs.chromium.org/p/project-zero/issues/detail?id=176)
* [Windows Kernel ATMFD.DLL read/write-what-where in LOAD and STORE operators](https://bugs.chromium.org/p/project-zero/issues/detail?id=177)
* [Windows Kernel ATMFD.DLL pool-based buffer overflow in Counter Control Hints](https://bugs.chromium.org/p/project-zero/issues/detail?id=178)
* [Windows Kernel ATMFD.DLL pool-based buffer underflow due to integer overflow in STOREWV](https://bugs.chromium.org/p/project-zero/issues/detail?id=179)
* [Windows Kernel ATMFD.DLL unlimited out-of-bounds stack manipulation via BLEND operator](https://bugs.chromium.org/p/project-zero/issues/detail?id=180)
* [Windows Kernel win32k.sys TTF font processing: pool-based buffer overflow in the IUP[] program instruction](https://bugs.chromium.org/p/project-zero/issues/detail?id=368)
* [Windows Kernel ATMFD.DLL OTF font processing: pool-based buffer overflow with malformed GPOS table](https://bugs.chromium.org/p/project-zero/issues/detail?id=369)
* [Windows Kernel win32k.sys TTF font processing: pool-based buffer overflow in win32k!scl_ApplyTranslation](https://bugs.chromium.org/p/project-zero/issues/detail?id=370)
* [Windows Kernel ATMFD.DLL out-of-bounds reads from the input CharString stream](https://bugs.chromium.org/p/project-zero/issues/detail?id=382)
* [Windows Kernel ATMFD.DLL invalid memory access due to malformed CFF table (ATMFD+0x34072 / ATMFD+0x3407b)](https://bugs.chromium.org/p/project-zero/issues/detail?id=383)
* [Windows Kernel ATMFD.DLL invalid memory access due to malformed CFF table (ATMFD+0x3440b / ATMFD+0x3440e)](https://bugs.chromium.org/p/project-zero/issues/detail?id=384)
* [Windows Kernel ATMFD.DLL write to uninitialized address due to malformed CFF table](https://bugs.chromium.org/p/project-zero/issues/detail?id=385)
* [Windows Kernel ATMFD.DLL out-of-bounds read due to malformed Name INDEX in the CFF table](https://bugs.chromium.org/p/project-zero/issues/detail?id=386)
* [Windows Kernel ATMFD.DLL out-of-bounds read due to malformed FDSelect offset in the CFF table](https://bugs.chromium.org/p/project-zero/issues/detail?id=392)
* [Windows Kernel win32k.sys TTF font processing: out-of-bounds pool memory access in win32k!fsc_RemoveDups](https://bugs.chromium.org/p/project-zero/issues/detail?id=401)
* [Windows Kernel win32k.sys TTF font processing: out-of-bounds pool write in win32k!fsc_BLTHoriz](https://bugs.chromium.org/p/project-zero/issues/detail?id=402)
