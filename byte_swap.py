#!/usr/bin/env python3
"""Reverse the byte order within each fixed-size block of a binary image.

Some boot sources present flash contents to the SoC with a different byte
order than the one the image is built in, so the image has to be swapped
before it is programmed. The input is first zero padded up to a multiple of
the block size, then the bytes of every block are reversed in place.
"""

import argparse
import sys


def byte_swap(data, block_size):
    """Zero pad data to a multiple of block_size and reverse each block."""
    padding = -len(data) % block_size
    data += b"\0" * padding
    swapped = b"".join(data[i:i + block_size][::-1]
                       for i in range(0, len(data), block_size))
    return swapped, padding


def positive_int(text):
    try:
        value = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("'%s' is not an integer" % text)
    if value < 1:
        raise argparse.ArgumentTypeError("block size must be 1 or greater")
    return value


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_file", help="image to read")
    parser.add_argument("output_file", help="image to write")
    parser.add_argument("block_size", type=positive_int,
                        help="size of the block to reverse, in bytes")
    args = parser.parse_args()

    try:
        with open(args.input_file, "rb") as handle:
            data = handle.read()
    except OSError as error:
        sys.stderr.write("Cannot read %s: %s\n"
                         % (args.input_file, error.strerror))
        return 1

    print("Size of file is %d" % len(data))
    swapped, padding = byte_swap(data, args.block_size)
    print("Appending %d bytes to make %d byte aligned"
          % (padding, args.block_size))

    try:
        with open(args.output_file, "wb") as handle:
            handle.write(swapped)
    except OSError as error:
        sys.stderr.write("Cannot write %s: %s\n"
                         % (args.output_file, error.strerror))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
