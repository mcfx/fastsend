# fastsend

A toy file send tool.

## Usage

Suppose you are sending file `/x/y/z` from machine `A` to `/u/v/w` on machine `B`.

First run the following command on `B`:

```shell
./fastsend create -filename /u/v/w -filesize SIZE
```

Here `SIZE` means the size of the file. If it fails to allocate space, a non-zero value will be returned.

Then run the following command on `B`:

```shell
./fastsend recv -filename /u/v/w -port PORT
```

Here `PORT` is the favorite port to connect with.

Finally run the following command on `A`:

```shell
./fastsend send -filename /x/y/z -addr IP:PORT
```

Here `IP` is the IP address of machine B.

You can also specify threads, block size, and encryption key. Use `./fastsend xxx -h` to discover.