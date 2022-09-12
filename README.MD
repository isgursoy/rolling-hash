## Rolling Hash Weekend

This repository is playing with [eqlabs recruitment exercise](https://github.com/eqlabs/recruitment-exercises/blob/8e49a7b8cf9c415466876e852fbd862f74105ec6/rolling-hash.md)
of `Rolling Hash Algorithm`.

Fork of [palucki/yardiff](https://github.com/palucki/yardiff) for boilerplate base. Simplified and refactored with these improvements:

* Generalized IO stream to accept also string stream.
* Ability to cleanup stream buffer to reuse IO object.
* Replaced Qt based MD4 strong checksum with independent header only MD5 implementation.
* Rolling checksum collision warning.
* Skipping unchanged segments to have hunk view like print.
* Reporting block coordinates and compared chunks.
* Alignment of matched reference and modified segments.
* Reporting edit operations of difference as addition/removal/substitution details.
* Producing metadata alongside terminal print.
* Builtin test.


### Documentation
You are there.

### Environment
  
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/std/the-standard)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://isocpp.org/std/the-standard)
  
[GNU](https://gcc.gnu.org/onlinedocs/libstdc++/manual/status.html#status.iso.2020): GCC 11.3.0 (Ubuntu 11.3.0-1ubuntu1~22.04)  

#### Dependencies

Given information is for Ubuntu 20.04. You should translate them to your distribution.

| **Project**                 | **Where to get**                                                                   | **Notes**                |
|:---------------------------:|:----------------------------------------------------------------------------------:|:-----------------------:|
| ```RapidFuzz```  | [maxbachmann/rapidfuzz-cpp](https://github.com/maxbachmann/rapidfuzz-cpp/releases/tag/v1.2.0)              | **Included** amalgamated header. Needed for levenshtein edit ops to report add/remove/substitution details.
| ```Hash```       | [Chocobo1/Hash](https://github.com/Chocobo1/Hash/blob/8672e783aeccd0b5026acd98f835b5266c8ff0d0/src/md5.h)  | **Included** md5 header. Needed for fast blockwise decision before rolling sequence.


#### Building
QMake pro file and generic Makefile are provided for your taste.

Here typical qmake based build-install procedure:
```bash
cd builDir
qmake path/to/root/pro/file.pro CONFIG+=release CONFIG+=THIS_IS_A_SWITCH "ARGUMENT=THIS_IS_A_VALUE"
make
make install
```

> Remember that you should clear builDir before recompiling program and additionally YOU MUST PASS "*." filename pattern to "rm" to be able to delete .qmake.super file which contains old qmake flags.

### Structure

```
├── main.cpp | Everything is here.
├── Makefile
├── md5.h
├── rapidfuzz_amalgamated.hpp
├── README.MD
├── rolling-hash.pro
└── test_material.hpp | Reference and modified test input strings. Just inputs.

0 directories, 7 files

```

#### App Flow

1. Have two file handles of A and B in `main()`.
2. Block by block walk over B and store rolling and strong checksums in `SignatureCalculator::calculate()`.
3. Shift block sized window with 1 hop size on A and compare stored strong checksums first and rolling hashes of B in case of mismatch in `DeltaCalculator::calculate()`.
4. Keep bytes of A between matched segments as the modification range. We are still in `DeltaCalculator::calculate()`. 
5. Locate and align corresponding raw data chunk of B by looking at the segment of A in `DeltaCalculator::align_cross_diff()`.
6. Have Levenshtein based modification report in terms of add/remove/replace in `DeltaCalculator::get_levenshtein_distance_ops_report()`.
7. Return hunk metadata and commit information to the print message. Finally leaving the `DeltaCalculator::calculate()`.






### Test
Just run as is. Builtin test will always run, even if a/b paths omitted.

Here what to expect:

<table>
<tr>
<th>
Reference
</th>
<th>
Output
</th>
<th>
Modified
</th>
</tr>

<tr>

<td>
<br>Rolling Hash Algorithm<br>    _Spec v4 (2021-03-09)_<br><br>    Make a rolling hash based file diffing algorithm. When comparing original and an updated version of an input, it should return a description ("delta") which can be used to upgrade an original version of the file into the new file. The description contains the chunks which:<br>    - Can be reused from the original file<br>    - have been added or modified and thus would need to be synchronized<br><br>    The real-world use case for this type of construct could be a distributed file storage system. This reduces the need for bandwidth and storage. If many people have the same file stored on Dropbox, for example, there's no need to upload it again.<br><br>    A library that does a similar thing is [rdiff](https://linux.die.net/man/1/rdiff). You don't need to fulfill the patch part of the API, only signature and delta.<br><br>    ## Requirements<br>    - Hashing function gets the data as a parameter. Separate possible filesystem operations.<br>    - Chunk size can be fixed or dynamic, but must be split to at least two chunks on any sufficiently sized data.<br>    - Should be able to recognize changes between chunks. Only the exact differing locations should be added to the delta.<br>    - Well-written unit tests function well in describing the operation, no UI necessary.<br><br>    ## Checklist<br>    1. Input/output operations are separated from the calculations<br>    2. detects chunk changes and/or additions<br>    3. detects chunk removals<br>    4. detects additions between chunks with shifted original chunk<br>
</td>

<td>
<pre>Signature: 48 blocks<br>### Delta ###<br>____________________________<br>|                          |<br>|        Begin Diff        |<br>|__________________________|<br>File block:0 (0-31) 	 <br>||||||||||||||||||||||||||||<br>Rolling Hash Algorithm<br>    _Spe<br>||||||||| +1 -0 ~0 |||||||||<br>aRolling Hash Algorithm<br>    _Spe<br>||||||||||||||||||||||||||||<br>____________________________<br>|                          |<br>|      Same So Far...      |<br>|__________________________|<br>File block:29 (862-928) 	 <br>||||||||||||||||||||||||||||<br><br>    ## Requirements<br>    - Hashing function gets the data as a pa<br>||||||||| +0 -1 ~1 |||||||||<br><br>    ## Requirements<br>    - Bashing function gets the dat as a pa<br>||||||||||||||||||||||||||||<br>____________________________<br>|                          |<br>|      Same So Far...      |<br>|__________________________|<br>File block:39 (1247-1279) 	 <br>||||||||||||||||||||||||||||<br>nction well in describing the o<br>||||||||| +1 -0 ~0 |||||||||<br>nction welll in describing the o<br>||||||||||||||||||||||||||||<br>____________________________<br>|                          |<br>|            Bye           |<br>|__________________________|<br>-----------------------------------------------<br>Test passed<br>-----------------------------------------------<br></pre>
</td>

<td>
<br>aRolling Hash Algorithm<br>    _Spec v4 (2021-03-09)_<br><br>    Make a rolling hash based file diffing algorithm. When comparing original and an updated version of an input, it should return a description ("delta") which can be used to upgrade an original version of the file into the new file. The description contains the chunks which:<br>    - Can be reused from the original file<br>    - have been added or modified and thus would need to be synchronized<br><br>    The real-world use case for this type of construct could be a distributed file storage system. This reduces the need for bandwidth and storage. If many people have the same file stored on Dropbox, for example, there's no need to upload it again.<br><br>    A library that does a similar thing is [rdiff](https://linux.die.net/man/1/rdiff). You don't need to fulfill the patch part of the API, only signature and delta.<br><br>    ## Requirements<br>    - Bashing function gets the dat as a parameter. Separate possible filesystem operations.<br>    - Chunk size can be fixed or dynamic, but must be split to at least two chunks on any sufficiently sized data.<br>    - Should be able to recognize changes between chunks. Only the exact differing locations should be added to the delta.<br>    - Well-written unit tests function welll in describing the operation, no UI necessary.<br><br>    ## Checklist<br>    1. Input/output operations are separated from the calculations<br>    2. detects chunk changes and/or additions<br>    3. detects chunk removals<br>    4. detects additions between chunks with shifted original chunk<br>
</td>

</tr>
</table>

## License
As free as dependencies.
