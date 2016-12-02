from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

setup(
    ext_modules = cythonize([
      Extension("dtls", ["dtls.pyx", "../dtls.c", "../crypto.c", "../ccm.c",
                         "../hmac.c", "../netq.c", "../peer.c", "../dtls_time.c",
                         "../session.c", "../dtls_debug.c", "../mc-helper.c",
                         "../aes/rijndael.c", "../sha2/sha2.c"],
                define_macros=[('DTLSv12', '1'),
                               ('WITH_SHA256', '1'),
                               ('DTLS_CHECK_CONTENTTYPE', '1'),
                               ('_GNU_SOURCE', '1')]
                )])
)
