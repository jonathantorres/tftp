## tftp
TFTP server and client with several changes for testing on modern UNIX-like machines. These changes were made so that it can compile on modern C compilers (gcc and clang). Original source code taken from "Unix Network Programming" 1st Edition by W. Richard Stevens

### Compiling and running
Use the `make` utility, once compiled run the server with `./bin/server` with default values.
```bash
make server
./bin/server
```

Run the client with `./bin/client`.
```bash
make client
./bin/client
```
