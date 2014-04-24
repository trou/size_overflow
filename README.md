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

##### gcc 4.5 - 4.9:

```shell
$ make clean; make
```

##### Usage

```shell
$ make run
```
