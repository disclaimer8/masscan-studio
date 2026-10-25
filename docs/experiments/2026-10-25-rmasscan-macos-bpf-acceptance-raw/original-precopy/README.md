# Original pre-copy hashes

`<dir>.sha256` is the `shasum -a 256` list of every file in the evidence directory as written on the stand. The list was taken before the copy into this repository, before personal paths in text files were replaced by `$HOME`/`$SCRATCH`/`$REPO`, and before the large captures were gzipped.

The scrub changes the bytes of text files, so their hashes here differ from the repository copies. The per-run `hashes-before-copy.txt` and each directory's `MANIFEST.sha256` describe the scrubbed copy. Pcaps and checkpoint binaries were not modified, so their hashes match here, and for the gzipped captures `PCAP-GZ-ORIGINALS.txt` matches as well.
