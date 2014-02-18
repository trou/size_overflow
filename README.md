size_overflow
=============

This plugin recomputes expressions of function arguments marked by a size_overflow attribute with double integer precision (DImode/TImode for 32/64 bit integer types).  The recomputed argument is checked against TYPE_MAX and an event is logged on overflow and the triggering process is killed.
