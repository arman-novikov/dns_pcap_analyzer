import platform
import multiprocessing as mp
if platform.system() == "Darwin":  # specially for MacOS
    mp.set_start_method('fork')  # to enable Queue
import time
import sys
import os
import glob
import json

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS

TOP_COUNT = 1000
PCAP_PART_SIZE = 500  # Mb
CPU_COUNT = mp.cpu_count()
results_queue = mp.Queue()


DNS_REQUEST = 0
DNS_RESPONSE = 1
DNS_NAME_ERROR = 3


class Stat:
    def __init__(self):
        self.total_dns_requests: int = 0
        self.failed_names = dict()
        self.requester_ips = dict()
        self.fail_requester_ips = dict()

    def add(self, stat):
        self.add_dns_req(stat.total_dns_requests)
        handler_data_map = {
            self.add_failed_name: stat.failed_names,
            self.add_requester_ip: stat.requester_ips,
            self.add_fail_requester_ip: stat.fail_requester_ips,
        }
        for handler, data in handler_data_map.items():
            for key, count in data.items():
                handler(key, count)

    def add_dns_req(self, count: int = 1):
        self.total_dns_requests += count

    def add_failed_name(self, name: str, count: int = 1):
        self.__inc_by_key(self.failed_names, name, count)

    def add_requester_ip(self, ip: str, count: int = 1):
        self.__inc_by_key(self.requester_ips, ip, count)

    def add_fail_requester_ip(self, ip: str, count: int = 1):
        self.__inc_by_key(self.fail_requester_ips, ip, count)

    def get_info(self, top: int) -> dict:
        top_failing_requesters = sorted(
            self.fail_requester_ips.items(),
            key=lambda x: x[1],
            reverse=True)[:top]
        top_failed_names = sorted(
            self.failed_names.items(),
            key=lambda x: x[1],
            reverse=True)[:top]

        res = {
            "total dns requests": self.total_dns_requests,
            "total unique failed domain names": len(self.failed_names),
            "total unique dns requesters": len(self.requester_ips),
            "total unique fail dns requesters": len(self.fail_requester_ips),
            f"top {top} failing requesters": top_failing_requesters,
            f"top {top} fail names": top_failed_names,
        }
        return res

    @staticmethod
    def __inc_by_key(dictionary, key: str, count: int):
        try:
            dictionary[key] += count
        except KeyError:
            dictionary[key] = count


def work(worker_id: int, packets):
    print(f"worker #{worker_id} starts")
    ts = time.time()
    stat = Stat()

    for pkt in packets:
        ether_pkt = Ether(pkt)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type': disregard those
            continue

        ip_pkt = ether_pkt[IP]
        try:
            udp_pkt = ip_pkt[UDP]
        except IndexError:
            continue

        # no TCP packets expected
        try:
            dns_packet = udp_pkt[DNS]
        except IndexError:
            continue

        if dns_packet.qr == DNS_REQUEST:
            stat.add_dns_req()
            continue

        rcode = dns_packet.rcode
        requester_ip = str(ip_pkt.dst)
        stat.add_requester_ip(requester_ip)
        if rcode == DNS_NAME_ERROR:
            try:
                requested_name = dns_packet.qd.qname.decode('utf-8')
            except AttributeError:
                continue
            except UnicodeDecodeError:
                # todo: take certain count (use multiplier?)
                continue
            if requested_name[-1] == ".":
                requested_name = requested_name[:-1]
            stat.add_fail_requester_ip(requester_ip)
            stat.add_failed_name(requested_name)

    results_queue.put(stat)
    print(f"worker #{worker_id} done. elapsed: {time.time() - ts}")


def get_data(pcap_file: str):
    print(f'Opening {pcap_file}')
    s = time.time()
    packets = [
        pkt_data for (pkt_data, pkt_metadata) in RawPcapReader(pcap_file)
    ]
    print(f"opening done, elapsed: {time.time() - s}; opened: {len(packets)}")
    return packets


def manage(source_file: str = "dns_tr.pcap") -> Stat:
    s = time.time()
    print("manager starts")
    data = get_data(source_file)
    bunch_len = len(data) // CPU_COUNT
    workers = []
    stat = Stat()

    for i in range(CPU_COUNT):
        if i != CPU_COUNT - 1:
            worker_data = data[i * bunch_len: (i + 1) * bunch_len]
        else:  # if the last part
            worker_data = data[i * bunch_len:]  # take all remained
        workers.append(mp.Process(target=work, args=(i, worker_data,)))
        workers[-1].start()

    for _ in workers:
        stat.add(results_queue.get())

    print(f"manager done, elapsed {time.time() - s}")
    return stat


def test_manage():
    stat: Stat = manage("part.pcap")
    with open('test_manage.json', 'w') as fp:
        json.dump(stat.get_info(10), fp, indent=4)


def split_pcap(source_file: str, each_size: int) -> [str]:
    part_name = "part_pcap"
    os.system(f"tcpdump -r {source_file} -w {part_name} -C {each_size}")
    return sorted(glob.glob("part_pcap*"))


def main():
    if len(sys.argv) != 3:
        exit(-22)
    ts = time.time()
    _, pcap_file, res_file = sys.argv
    parts: [str] = split_pcap(pcap_file, PCAP_PART_SIZE)

    print(f"preparations done, elapsed {time.time() - ts}")
    stat = Stat()
    for part in parts:
        stat.add(manage(part))
        print(f"{part} processed")

    print(f"managing done, elapsed {time.time() - ts}")
    for part in parts:
        os.system(f"rm {part}")
    with open(res_file, 'w') as fp:
        json.dump(stat.get_info(TOP_COUNT), fp, indent=4)
    print(f"main done, elapsed {time.time() - ts}")


if __name__ == "__main__":
    main()
