# ECHM

Implementation of the multiset hash using elliptic curves algorithm described in [ecmh.wiki]. Uses the secp256k1 curve and SHA256 as input.

This is a port of a [JS implementation](https://github.com/arj03/ecmh-js) to C#.

The purpose of this port was: 
 - To use AI tools to help port code to another language and to improve the code with a focus on performance.
 - To check the performance difference between JS and a compiled language like C#.

Please note that the JS implementation also uses a JS implementation of the secp256k1 crypto, so it's not an entirely fair comparison. 
C# is around 8-10 times faster.

I used Claude and more recently DeepSeek to help in this task. I have spent probably more hours fixing code and writing prompts that it
would have taken me to just write the code myself. Often the code would not even compile, not to mention passing tests. I really wish 
there was an option to at least compile the code. On the other hand I have learned quite a few new tricks. Especially the thinking mode
in DeepSeek is very good at coming up with correct and useful code and explaining why. These optimizations have reduced the time in perf.cs
from around 54ms to around 41ms. Furthermore some of the last refactors also made the code more readable.

[ecmh.wiki]: https://github.com/tomasvdw/bips/blob/master/ecmh.mediawiki
