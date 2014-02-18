size_overflow
=============

This plugin recomputes expressions of function arguments marked by a size_overflow attribute with double integer precision (DImode/TImode for 32/64 bit integer types). The recomputed argument is checked against TYPE_MAX and an event is logged on overflow and the triggering process is killed.

Homepage
--------

http://www.grsecurity.net/~ephox/overflow_plugin/

Documentation
-------------

http://forums.grsecurity.net/viewtopic.php?f=7&t=3043


Compiling & Usage
-----------------

##### gcc 4.5 - 4.7 (C):

```shell
$ gcc -I`gcc -print-file-name=plugin`/include -I`gcc -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o size_overflow_plugin.so size_overflow_plugin.c
```

##### gcc 4.7 (C++) - 4.8+

```shell
$ g++ -I`g++ -print-file-name=plugin`/include -I`g++ -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o size_overflow_plugin.so size_overflow_plugin.c
```

##### Usage

```shell
$ gcc -fplugin=./size_overflow_plugin.so test.c -O2
```
