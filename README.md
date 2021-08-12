# The Use of Likely Invariants as Feedback for Fuzzers

This prototype implements the idea described in our [USENIX Security '21 paper](http://s3.eurecom.fr/docs/usenixsec21_fioraldi.pdf), a new feedback mechanism that
augments code coverage by taking into account the usual
values and relationships among program variables. For this
purpose, we learn likely invariants over variables at the basic-
block level, and partition the program state space accordingly.
Our feedback can distinguish when an input violates one or
more invariants and reward it, thus refining the program state
approximation that code coverage normally offers.

Bibtex:

```bibtex
@inproceedings {usenixsec21fioraldi,
  author = {Andrea Fioraldi and Daniele Cono D'Elia and Davide Balzarotti},
  title = {The Use of Likely Invariants as Feedback for Fuzzers},
  affiliations = {EURECOM, {Sapienza University of Rome}},
  booktitle = {30th {USENIX} Security Symposium ({USENIX} Security 21)},
  year = {2021},
  url = {https://www.usenix.org/conference/usenixsecurity21/presentation/fioraldi},
  publisher = {{USENIX} Association},
  month = aug,
}
```

## Build

LLVM 10 is required. It may work with more recent versions but it is untested.

Build the fuzzer and the passes with:

```
make -C InvsCov/dump LLVM_CONFIG=llvm-config-10
make -C InvsCov/instrument LLVM_CONFIG=llvm-config-10
make -C AFLplusplus
make -C AFLplusplus/llvm_mode LLVM_CONFIG=llvm-config-10
```

To compile Daikon, follow the steps in the Daikon readme and copy the resulting `daikon.jar` in the root folder of this project.

## Usage

+ set the env var `INVSCOV_OUTPUT_PATH` to an existing empty folder
+ compile the PUT with InvsCov/dump-cc/c++
+ run InvsCov/reconstruct-dump
+ run InvsCov/learn-invariants with the dumper binary produced in the second step
+ run InvsCov/generate-constraints
+ compile with InvsCov/instrument-cc/c++
+ fuzz this last binary with AFLplusplus/afl-fuzz

### License

The modification to the AFL++ and Daikon codebases are released under the same license of the modified package.

The InvsCov code is released under Apache-2.
