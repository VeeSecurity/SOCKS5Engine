# SOCKS5 Engine

A highly-customizable lightweight SOCKS5-server supporting RADIUS, Redis, subnet whitelisting and blacklisting, session counting.

For SOCKS5 protocol specification, consult https://www.ietf.org/rfc/rfc1928.txt.  
For details on username/password SOCKS5 authentication, consult https://tools.ietf.org/html/rfc1929.

This version of SOCKS5 Engine supports username/password authentication (METHOD 02) and no authentication (METHOD 01).  
It supports CONNECT and UDP ASSOCIATE (fragmentation is not implemented) requests.

## Usage

To run SOCKS5 Engine, specify the `-conf=<full path to the config>` flag. `/etc/vee-socks5/config.conf` is assumed to be the default config location.

VPE listens for `SIGUSR1` signals and displays data about idle workers and the connection queue on `SIGUSR1`.

Use the `-h` flag to see the configuration details.  
Use the `-v` flag to see the version of your build.

## Configuration

We advise that you set this up as a system service.  
If you are willing to use RADIUS for authentication, we highly recommend running Redis for caching.  
No matter what authentication scheme you choose, it makes sense to run Redis to keep track of your users' sessions.

For the detailed documentation and a configuration example, see [config.conf](https://github.com/VeeSecurity/SOCKS5Engine/blob/master/config.conf).
