# ECHM

Implementation of the multiset hash using elliptic curves algorithm described in [ecmh.wiki]. Uses the secp256k1 curve and SHA256 as input.

This is a port of a [JS implementation](https://github.com/arj03/ecmh-js) to C#.

The purpose of this port are several: use AI tools to help port code to another language and to improve the code for better performance. 
To check the performance difference between JS and a compiled language like C#. Please note that the JS implementation also uses a JS 
implementation of the secp256k1 crypto, so it's not an entirely fair comparison. C# is around 8-10 times faster.

[ecmh.wiki]: https://github.com/tomasvdw/bips/blob/master/ecmh.mediawiki
