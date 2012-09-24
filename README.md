microhttpd_utils
================

 * Author: Tom Wambold <tom5760@gmail.com>
 * Copyright (c) 2012 Tom Wambold

Purpose
-------

`microhttpd_utils` provides a few convenience functions on top of what [GNU
libmicrohttpd][libmicrohttpd] already provides, providing a sort-of micro web
framework for C.

[libmicrohttpd]: http://www.gnu.org/software/libmicrohttpd/

Features
--------

Currently implemented:
 * Regular-expression based URL routing.

Requirements
------------

 * C99 compiler (tested with GCC 4.7.1 and clang 3.1)
 * [libmicrohttpd][libmicrohttpd] (tested with 0.9.22)
 * [uthash][uthash] (1.9.6 included in "deps" directory)
 * [tj-tools][tj-tools] (2012-09-24 included in "deps" directory)

[uthash]: http://uthash.sourceforge.net/
[tj-tools]: http://code.google.com/p/tj-tools/

Building
--------

`microhttpd_utils` consists of just one C file and one header, so you could
just drop them into your project and build it with the rest of your program.
Otherwise, you can build a static library with:

    ./waf configure build

This will put a static library "libmicrohttpd_utils.a" in the "build"
directory.

Usage
-----

See the test programs in the "test" directory for now.

License
-------

See the LICENCE file in the distribution.
