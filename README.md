# Spectre Variant 2 PoC

Proof of Concept of Spectre Variant 2 vulnerability.  

[Spectre](https://spectreattack.com/spectre.pdf) is a vulnerability that
allows malicious programs to read arbitrary memory locations by exploiting
microarchitectural side channels and speculative execution.

Variant 1 of Spectre relies on mistraining the CPUs branch predictor, in order
to speculatively execute a code path that is logically prevented by a
conditional branch.

Variant 2 is very similar, but instead relies on mistraining the CPUs branch
**target** predictor. For more details,
[here](https://antoncao.me/blog/spectre) is a shameless plug to a blog post 
I wrote on the topic.

## How to Run
Take it one step at a time:
```
$ make
$ ./spectrev2
...output...
```
If you see the secret phrase, that means the demo worked! If not, the code might
not be set up correctly for your system. Feel free to leave a GitHub issue, or
submit a pull request if you were able to fix it.

## Acknowledgements
This code was written while I was working on the project
[Ward](https://github.com/mit-pdos/ward).

The Makefile was taken from Eugnis'
[repository](https://github.com/Eugnis/spectre-attack) for a PoC of the Spectre
v1 attack.
