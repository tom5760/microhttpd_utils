#!/usr/bin/env python
# Copyright (c) 2012 Tom Wambold <tom5760@gmail.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
'''
    microhttpd_utils - Utility functions for microhttpd
    wscript - Waf build script, see http://waf.googlecode.com for docs
'''

def options(ctx):
    ctx.load('compiler_c')

    opts = ctx.add_option_group('Build Options')
    opts.add_option('--debug', action='store_true',
                    help='Build with debugging flags (default optimized).')

def configure(ctx):
    ctx.load('compiler_c')
    ctx.check_cc(lib='microhttpd')

    if ctx.env.CC_NAME == 'gcc':
        ctx.env.CFLAGS += ['-std=gnu99', '-Wall', '-Wextra', '-Werror',
                           '-Wno-unused-parameter']

        if ctx.options.debug:
            ctx.env.CFLAGS += ['-O0', '-g']
        else:
            ctx.env.CFLAGS += ['-O3']
            ctx.env.DEFINES += ['NDEBUG']

def build(ctx):
    ctx.stlib(
        target = 'microhttpd_utils',
        use = 'MICROHTTPD',
        includes = [
            'deps/tj-tools/src',
            'deps/uthash/src',
        ],
        export_includes = [
            'src',
            'deps/tj-tools/src',
            'deps/uthash/src',
        ],
        source = [
            'deps/tj-tools/src/tj_buffer.c',
            'src/microhttpd_utils.c',
        ],
    )

    ctx.program(
        target = 'test1',
        use = 'microhttpd_utils',
        source = 'test/test1.c',
    )
