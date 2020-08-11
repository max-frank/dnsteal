# dnsteal v 2.0 (with support for public dns-infrastructure)

==== MODIFICATIONS ====

NOTE: this version of dnsteal is modified to allow the usage with the public dns infrastructure.
To get this working the format of dns queries was changed to:

3x6-.{index}-.data_0.data_1....data_n.file.name.authorative.domain

* Label 1: The 3x6 is just a magic number to identify valid requests.
* Label 2: The index of the payload is now also transimtted. A recursive resolver may send a request twice if we dont respond in time. Sending the index allows us to filter out duplicates and also see if a dns-message went missing somewhere.

WARNING: These modifications reduce the payload capacity of dnsteal.
We now need 5 bytes for magic-nr (4 bytes + 1 length-byte). Also the index takes (length of index) + 2 bytes. 
Also our authorative server domain name needs to be at the end of the qname, so that we actually get the messages. 

=======================

This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests. 

Below are a couple of different images showing examples of multiple file transfer and single verbose file transfer:

![Alt text](http://i.imgur.com/nJsoAMv.png)

* Support for multiple files
* Gzip compression supported
* Now supports the customisation of subdomains and bytes per subdomain and the length of filename

See help below:

![Alt text](http://i.imgur.com/GT5SV2L.png)

If you do not understand the help, then just use the program with default options!

```bash
python dnsteal.py 127.0.0.1 -z -v
```

This one would send 45 bytes per subdomain, of which there are 4 in the query. 15 bytes reserved for filename at the end.

```bash
python dnsteal.py 127.0.0.1 -z -v -b 45 -s 4 -f 15
```

This one would leave no space for filename.

```bash
python dnsteal.py 127.0.0.1 -z -v -b 63 -s 4 -f 0
```
