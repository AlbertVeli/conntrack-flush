# conntrack-flush

Flush conntrack state table using the [netfilter netlink library](https://netfilter.org/).

It is possible To flush the whole table using the standard conntrack tools.
This tool allows for exclusion of some ports from the flush. Just give the
port numbers to exclude as argument.

### Requirements

The following libs from the netfilter netlink library:

* libnfnetlink
* libnetfilter\_conntrack
* libmnl

### Example

Flush the whole state table except SSH, HTTP and HTTPS connections.

```
conntrack-flush 22 80 443
```

### License
GPLv2 since it links against the netfilter netlink library which is licensed
according to GPLv2.
