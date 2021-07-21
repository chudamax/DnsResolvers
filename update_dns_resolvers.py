  #!/usr/bin/env python3

__author__      = "Maksim Chudakov aka Izzet"

import dnslib
import threading
import queue
import uuid
import argparse
import sys
import requests

class DNSWorker(threading.Thread):

    def __init__(self, queue, output_list):
        threading.Thread.__init__(self)
        self.queue = queue
        self.output_list = output_list
        self.random_domain = uuid.uuid4().hex + ".com"

    def run(self):
        while True:
            nameserver = self.queue.get()

            print ('(.) Candidates to check: {}'.format(self.queue.qsize()), end="\r", flush=True)

            response1 = self.lookup('dns.google', nameserver=nameserver)
            if len(response1) == 0:
                self.queue.task_done()
                continue

            if not {'domain': 'dns.google', 'rtype': 'A', 'rdata': '8.8.8.8'} in response1:
                self.queue.task_done()
                continue

            response2 = self.lookup(self.random_domain, nameserver=nameserver)
            if len(response2) > 0:
                self.queue.task_done()
                continue

            self.output_list.append(nameserver)
            self.queue.task_done()

    @staticmethod
    def lookup(name, nameserver):
        results = []

        use_tcp = False
        response = None
        query = dnslib.DNSRecord.question(name)

        try:
            response_q = query.send(nameserver, 53, use_tcp, timeout=3)
            if response_q:
                response = dnslib.DNSRecord.parse(response_q)
       

            if response: 
                rcode = dnslib.RCODE[response.header.rcode]
                if rcode == 'NOERROR' or rcode == 'NXDOMAIN':
                    # success, this is a valid subdomain

                    for r in response.rr:

                        rtype = None
                        try:
                            rtype = str(dnslib.QTYPE[r.rtype])
                        except:
                            rtype = str(r.rtype)

                        domain = str(r.rname)
                        if domain[-1:]=='.':
                            domain=domain[:-1]

                        rdata = str(r.rdata)
                        if rdata[-1:]=='.':
                            rdata=rdata[:-1]

                        results.append({'domain':domain, 'rtype':rtype, 'rdata':rdata})
        except Exception as err:
            return []
            # probably socket timed out

        return results

class DnsResolverProvider():

    def __init__(self, threads = 20):
        self.threads = threads

    def get_good_resolvers(self, resolver_list):

        q = queue.Queue()
        output_list = []

        for i in range(self.threads):
            worker = DNSWorker(queue=q, output_list=output_list)
            worker.setDaemon(True)
            worker.start()

        for resolver in resolver_list:
            q.put(resolver)

        q.join()

        return output_list

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg)
    sys.exit()

def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -h 127.0.0.1 -p 11211 -w /usr/share/wordlist/all.txt")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-l', '--local_file', help="local resolver file path")
    parser.add_argument('-o', '--output', help="output file path", required=True)
    parser.add_argument('-t', '--threads', help="checkers count", type=int, default = 20)
    parser.add_argument('-u', help="update from public sources", action='store_true')

    return parser.parse_args()
    
def main():
    args = parse_args()

    dns_provider = DnsResolverProvider(args.threads)
    resolver_list = []

    if args.local_file:
        with open (args.local_file) as f:
            resolver_list += [s.strip() for s in f.readlines()]

    if args.u:
        with open ("sources.txt") as f:
            sources = [s.strip() for s in f.readlines()]
        print ("(.) Loading the external list...")

        for s in sources:
            candidates = requests.get(s).text.split("\n")
            resolver_list += candidates
            print ("(+) Got {0} candidates from {1}".format(len(candidates), s))

    candidate_resolver_list = list(set(resolver_list))
    print ("(.) Unique candidates to test: {0}".format(len(candidate_resolver_list)))

    good_resolvers = dns_provider.get_good_resolvers(resolver_list=candidate_resolver_list)
    
    if args.output:
        with open(args.output,'w') as f:
            for resolver in good_resolvers:
                f.write("{0}\n".format(resolver))


    print ("(+) {0} candidates were checked".format(len(candidate_resolver_list)))
    print ("(+) {0} good resolvers have been added to {1}".format(len(good_resolvers),args.output))

if __name__ == '__main__':
    main()