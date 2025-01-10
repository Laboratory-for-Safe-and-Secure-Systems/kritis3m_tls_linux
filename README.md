# KRITIS³M TLS Application for Linux (and Windows)

This repository contains the code for the main TLS application to be used in the KRITIS³M research project.

**Disclaimer:** It is recommended to consume this repository indirectly via the [KRITIS³M Workspace repository](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_workspace).


## Building

The project uses CMake to be built. A single CLI tool is the output of the build.

```bash
mkdir build && cd build
cmake [options] ..
make
sudo make install
```

You can also use Ninja as a build tool by specifying `-GNinja` within the CMake invocation.

The CLI tool has a few dependencies listed below. By default, those are cloned using the CMake FetchContent functionality. However, you can also specify their source directory via CMake variables (given below for each dependency) to prevent additional downloads.

* [kritis3m_applications](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications): common code for CLI applications (`-DFETCHCONTENT_SOURCE_DIR_KRITIS3M_APPLICATIONS=/path/to/kritis3m_applications`).
* [kritis3m_asl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl): Agile Security Library used for TLS connections.
* [kritis3m_wolfssl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_wolfssl): Wrapper repository for the WolfSSL fork and the liboqs library with the specific configuration of both libraries (`-DFETCHCONTENT_SOURCE_DIR_KRITIS3M_WOLFSSL=/path/to/kritis3m_wolfssl`).
* [wolfssl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/wolfssl): KRITIS³M fork of WolfSSL with downstream changes (`-DFETCHCONTENT_SOURCE_DIR_WOLFSSL=/path/to/wolfssl`).
* [liboqs](https://github.com/open-quantum-safe/liboqs): Library for support of the PQC algorithm FALCON (`-DFETCHCONTENT_SOURCE_DIR_LIBOQS=/path/to/liboqs`).

The resulting CLI tool is installed in the default CMake installation paths. Another install path may be specified via the default CMake `CMAKE_INSTALL_PREFIX` variable.

### CLI build options

The following additional CMake options are available to customize the compilation of the CLI tool:

* `KRITIS3M_TLS_SELF_CONTAINED`: When enabled, the application will be built as a self-contained executable with all dependencies statically included. When disabled, the tool dynamically loads the dependencies at runtime. Default: `OFF`.
* `KRITIS3M_TLS_EXTERNAL_ASL`: Use an externally installed ASL library (searched using CMake `find_package()`). If disabled, the ASL will be built. Default: `OFF`.


### Bash completions

For the CLI tool, a script with bash completions is provided in the `scripts/` directory.


### Helper scripts

In addition, a few helper scripts are provided to ease the usage of the `kritis3m_tls` CLI tool. These can be found in the `scripts/` directory and are also installed system-wide during the install step. These scripts mainly ease the CLI arguments for certificates and are dependent on the certificate file structure of the [kritis3m_workspace](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_workspace) repository.


## Usage

In the following, key usage aspects of the CLI tool `kritis3m_tls` are discussed.

By default, the tool only creates output in case of an error. Verbose output can be enabled with `-v` or `--verbose`, debug output with `-d` or `--debug`. Thorough help information can be printed with `-h` or `--help`.

In general, the first argument of the application is the role that should be executed. After that, multiply additional options can be provided, which depend on the selected role.

### Roles

The tools supports various roles, which mainly reflect the available applications in the [kritis3m_applications](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications) repository.

With each invocation, the instance of the application takes one role.

* `reverse_proxy`: Reverse proxy mapping incoming TLS connections to outgoing TCP connections. Once the connections are established, full-duplex communication is possible.
* `forward_proxy`: Forward proxy mapping incoing TCP connections to outgoing TLS connections. Once the connections are established, full-duplex communication is possible.
* `echo_server`: Wait for incoming TLS connections and echo all received data back to the client.
* `tls_client`: Establish a TLS connection to a remote server. Once the connection is established, all stdin data is sent to the server and all received data from the server is printed to stdout.
* `network_tester`: Measure TLS handshake duration and message roundtrip latency with a remote TLS server.
* `management_client`: Obtain the application role and all remaining options from a central controller server.

The two additional roles "echo_server_proxy" and "network_tester_proxy" do exactly the same as their equivalents without the suffix, but by using a reverse/forward proxy internally instead of directly handling the TLS connection. This is only used for internal testing.

For all network connection related settings, two CLI arguments are used.
* `--incoming <ip>:port`: Wait for incoming TCP/TLS connections on given port (on the network interface with given IP address). If no IP address is given, all interfaces are used. Both IPv4 and IPv6 addresses and also domain names for `<ip>` are supported. IPv6 addresses must be wrapped in "[ ]" to enable the port separation.
* `--outgoing ip:port`: Establish a TCP/TLS connection to the peer at given IP address on given port. Both IPv4 and IPv6 addresses and also domain names for `<ip>` are supported. IPv6 addresses must be wrapped in "[ ]" to enable the port separation.


### Certificates and Private Keys

For TLS endpoints, certificates and a privat key are necessary. For its own identity, a certificate chain and the correspondig private key are required. These can be provided by the following arguments:
* `--cert`: Path to the certificate of the endpoint in PEM format. This file may also contain the full certificate chain (excluding the root certificate).
* `--intermediate`: If the certificate file does not contain the intermediate certificate(s), they can be provided with this argument (again in PEM format).
* `--key`: Path to the corresponding private key (in PEM format). In case of a hybrid certificate, this file may also contain the additional private key.
* `--additional_key`: Path to the additional private key for a hybrid certificate, in case the additional key is not present in the primary key file.

In case the TLS endpoint need not to authenticate itself to a peer (e.g. a TLS client connects to a server without mutual authentication), the certificates and private keys may be omitted.

For verification of a peer certificate chain, a root certificate must be provided. This can be done via the `--root` argument. This takes a path to a PEM file containing one or more root certificates. If no peer verification will be performed (e.g. in case of a TLS server with mutual authentication disabled), the root certificate may be omitted.

### PKCS#11 support

The application supports private keys that are stored on a PKCS#11 token. The private keys on the token are identified using a label string. To provide this label to the application, two options are available.
* Instead of giving the two arguments `--key` and `--additional_key` a path to a PEM file, you can give them the PKCS#11 key label, prepending it with the string "pkcs11:" (e.g. `--key pkcs11:KEY_LABEL`).
* The file given to one of the arguments contains a string of the form "pkcs11:KEY_LABEL" as its content instead of PEM data.

To interact with a PKCS#11 token, a middleware library is necessary. The path to this file must be provided via the argument `--pkcs11_module`. Once the application detects a PKCS#11 key label during TLS endpoint initialization, it loads the middleware library and references the private key. All private key operations are then executed on the token without the private key leaving the token. In case the module requires a PIN to use the key, you can provide that with `--pkcs11_pin`.

In addition to the private key operations, all other cryptographic operations may also be offloaded to the PKCS#11 library. This feature can be enabled with the argument `--pkcs11_crypto_all`. In case the library does not support a cryptographic feature, the main crytpo code of the application is used as a fallback.

### Security Configuration

Next to the certificates and private keys, the following additional security configuration options are available:
* `no_mutual_auth`: Flag to disable mutual authentication. Only relevant for server endpoints.
* `integrity_only_cipher`: Flag to force the usage of the integrity-only cipher-suite "TLS_SHA384_SHA384" instead of the default "TLS13_AES256_GCM_SHA384". Only relevant for client entpoints.
* `key_exchange_alg`: Select the key exchange algorithm to be used for the intial TLS ClientHello message. The default one is the hybrid `secp384_mlkem768`. In case the server does not support the selected algorithm and a HelloRetryRequest message is sent, the client automatically uses another supported algorithm.

Currently, the following key exchange algorithms are supported:
* Classic: `secp256`, `secp384`, `secp521`, `x25519`, `x448`
* PQC: `mlkem512`, `mlkem768`, `mlkem1024`
* Hybrid: `secp256_mlkem512`, `secp384_mlkem768`, `secp256_mlkem768`, `secp521_mlkem1024`, `secp384_mlkem1024`, `x25519_mlkem512`, `x448_mlkem768`, `x25519_mlkem768`

### Keylog-File support

To decrypt recorded TLS traffic, e.g. with Wireshark, the tools supports the creation of a keylog-file. With the argument `--keylog_file`, you can provide a path to a keylog-file. In case the file doesn't exist, it is created.


### Network Tester options

The network_tester role provides functionality to test a TLS echo server endpoint and aquire timing metrics regarding TLS handshake time and message roundtrip time. The main program flow of the application in this role is to establish the given amount of TLS handshakes. After each handshake, the given amount of messages with the given byte length are sent and waited for the echo. At the end, various statistics are printed.

In addition, an output path can be provided. At that path, a CSV file will be created for each of the two measurement types to store all time measurements for later analysis.

The following arguments are available to configure the test:
* `--test_num_handshakes`: Amount of handshakes to perform. May be 0 to disable the handshake measurement. In this case, one handshake is performed to enable the message latency measurement. Default is 1.
* `--test_handshake_delay`: Delay in milliseconds inbetween two TLS handshakes. Default 0.
* `--test_num_messages`:  Amount of messages to send after each handshake. Can be zero to disable the message latency measurement.
* `--test_message_delay`: Delay in microseconds inbetween two messages. Default 0.
* `--test_message_size`: Size of the message in bytes. Default 1.
* `--test_output_path`: Path where to store the CSV files. If this argument is omitted, no CSVs are created.
* `--test_no_tls`: Disable TLS and only use TCP for the two measurement types.
* `--test_silent`: Do not print test progress, even when verbose output is enabled.

Verbose output including a progress bar can be enabled with `-v` or `--verbose`.

### Management Service

The management client application connects to the control server, retrieves configurations, and starts the `kritis3m_applications` module (reverse and forward proxy) based on the configurations provided by the server.

The startup parameters for the management client are specified in the `configfile.json`. This file contains the following information:

- An identifier used by the server to match the correct configuration with the management client.
- The server address required for establishing the connection to the control server.
- File paths to the certificate locations.
- A file path specifying the location where the management client stores the configurations retrieved from the server.

### Examples

#### TLS echo server
```bash
kritis3m_tls echo_server --incoming 4433 --cert /path/to/chain.pem \
                         --key /path/to/key.pem --root /path/to/root.pem
```

#### TLS echo server without mutual authentication
```bash
kritis3m_tls echo_server --incoming 4433 --cert /path/to/chain.pem \
                         --key /path/to/key.pem --no_mutual_auth
```
Root certificate is omitted as no peer authentication takes place.

#### TLS echo server with private key on PKCS#11 token
```bash
kritis3m_tls echo_server --incoming 4433 --root /path/to/root.pem \
                         --cert /path/to/chain.pem --key pkcs11:KEY_LABEL \
                         --pkcs11_module /path/to/library.so
```
This assumes that on the PKCS#11 token the private key for the certificate is already present and can be found using the label "KEY_LABEL". Alternatively, you can specify a path to a file containing the string "pkcs11:KEY_LABEL".

#### TLS client with mutual authentication to local server
```bash
kritis3m_tls tls_client --outgoing localhost:4433 --cert /path/to/chain.pem \
                        --key /path/to/key.pem --root /path/to/root.pem
```

#### TLS client without mutual authentication to external IPv4 server
```bash
kritis3m_tls tls_client --outgoing 192.168.0.10:4433 --root /path/to/root.pem
```

#### TLS client without mutual authentication to external IPv6 server
```bash
kritis3m_tls tls_client --outgoing [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:4433 \
                        --root /path/to/root.pem
```

#### Forward Proxy
```bash
kritis3m_tls forward_proxy --incoming 8080 --outgoing 192.168.0.10:4433 \
                           --cert /path/to/chain.pem --key /path/to/key.pem \
                           --root /path/to/root.pem
```
Wait for incoming TCP connections on port 8080. When a TCP connection is established, a TLS connection is established to the remote host at 192.168.0.10 on port 4433. After both connections are up, all messages in both directions are forwarded to the other peer.

#### Reverse Proxy
```bash
kritis3m_tls reverse_proxy --incoming 4433 --outgoing 192.168.0.10:8080 \
                           --cert /path/to/chain.pem --key /path/to/key.pem \
                           --root /path/to/root.pem
```
Wait for incoming TLS connections on port 4433. When a TLS connection is established with a trusted peer, a TCP connection is established to the remote host at 192.168.0.10 on port 4433. After both connections are up, all messages in both directions are forwarded to the other peer.

#### Network Tester
```bash
kritis3m_tls network_tester --outgoing 192.168.0.10:4433 --test_num_handshakes 100 \
                            --test_handshake_delay 10 --test_num_messages 100 \
                            --test_message_delay 50 --test_message_size 512 \
                            --test_output_path /path/to/csv/files -v
```
Start a test with the TLS echo server at 192.168.0.10 on port 4433. We perform 100 handshakes with a delay of 10 milliseconds between the handshakes. After each handshake, 100 messages with 512 bytes are sent to the server with a delay of 50 microseconds between the messages. The aquired measurement values for handshake time and message latency are stored in two CSV files in the directory `/path/to/csv/files/` Furthermore, statistics of the test (average, mean etc.) are printed to stdout.

#### Management Service
```bash
kritis3m_tls management_client --mgmt_path /path/to/configfile.json
```
Depending on the information in the `configfile.json`, the actual config of the endpoint is obtained from the management service controller. After that, the requested applications (reverse_proxy etc.) are started.
