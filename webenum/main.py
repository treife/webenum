import asyncio
import argparse
import datetime
import json
import sys
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import dns


async def scan_subdomains(path: str, wordlist: list[str], depth: int, num_threads: int, proxy: str, quiet: bool):
    if proxy:
        raise NotImplementedError('proxy is not implemented')
    assert depth > 0
    assert num_threads > 0
    assert len(wordlist) > 0

    def job_worker(fqdn: str, ns: str) -> list[tuple[str, str]] | None:
        try:
            records = dns.query(fqdn, ns, 'A')
            return records
        except dns.NotFoundError as e:
            return None

    jobs = []

    try:
        wildcard_record = dns.query('*.' + path, '1.1.1.1', 'A')
        wildcard_addrs = [addr for _, addr in wildcard_record]
        if wildcard_record:
            print(f'*.{path} > {wildcard_addrs}')
        wildcard_addrs = set(wildcard_addrs)
    except dns.NotFoundError:
        wildcard_addrs = set()

    async def exec_jobs():
        if len(jobs) == 0:
            return []
        scheduled = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for job in jobs:
                scheduled.append(executor.submit(*job))
            results = []
            for job in scheduled:
                result: dict = job.result()
                if result is None:
                    # No such name
                    continue
                if len(result) == 0:
                    # No records
                    continue
                if set([addr for _, addr in result]) == wildcard_addrs:
                    continue
                if not quiet:
                    grouped_results = {}
                    for i, rec in enumerate(result):
                        dn, addrs = rec
                        if dn not in grouped_results:
                            grouped_results[dn] = addrs
                        else:
                            grouped_results[dn].extend(addrs)
                        for domain, addrs in grouped_results.items():
                            print(f'{domain} > {addrs}')
                results.append(result)
            return results

    # indices[k] - wordlist index for kth segment
    indices = [0] * len(wordlist)
    found = []
    while True:
        segments = []
        complete_seg = False
        for seg_i in range(depth-1, -1, -1):
            if indices[seg_i] == len(wordlist):
                if seg_i == 0:
                    segments.clear()
                    break
                else:
                    indices[seg_i-1] += 1
                    for j in range(seg_i, depth):
                        indices[j] = 0
            segments.append(wordlist[indices[seg_i]])
            if not complete_seg:
                indices[seg_i] += 1
                complete_seg = True
        if not segments:
            break
        req_path = '.'.join(segments[::-1])

        full_path = req_path + '.' + path

        jobs.append((job_worker, full_path, '1.1.1.1'))
        if len(jobs) == num_threads:
            found.extend(await exec_jobs())
            jobs.clear()

    # Make sure the last batch gets executed in case it doesn't exceed the thread pool size
    found.extend(await exec_jobs())

    return found


async def scan_uris(path: str, wordlist: list[str], depth: int, num_threads: int, trailing_slash: bool, proxy: str,
                    quiet: bool):
    assert depth > 0
    assert num_threads > 0
    assert len(wordlist) > 0

    def job_worker(req_path: str) -> requests.Response:
        result = requests.get(req_path, proxies={
            'http': proxy,
            'https': proxy
        })
        return result

    jobs = []

    async def exec_jobs():
        if len(jobs) == 0:
            return []
        scheduled = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for job in jobs:
                scheduled.append(executor.submit(*job))
            results = []
            for job in scheduled:
                result: requests.Response = job.result()
                if result.status_code == 404:
                    continue
                if not quiet:
                    print(f'[{result.status_code}] {result.url}')
                results.append(result)
            return results

    # indices[k] - wordlist index for kth segment
    indices = [0] * len(wordlist)
    found = []
    while True:
        segments = []
        complete_seg = False
        for seg_i in range(depth-1, -1, -1):
            if indices[seg_i] == len(wordlist):
                if seg_i == 0:
                    segments.clear()
                    break
                else:
                    indices[seg_i-1] += 1
                    for j in range(seg_i, depth):
                        indices[j] = 0
            segments.append(wordlist[indices[seg_i]])
            if not complete_seg:
                indices[seg_i] += 1
                complete_seg = True
        if not segments:
            break
        req_path = '/'.join(segments[::-1])
        if trailing_slash:
            req_path += '/'

        full_path = path
        if full_path[-1] != '/':
            full_path += '/'
        full_path += req_path

        jobs.append((job_worker, full_path))
        if len(jobs) == num_threads:
            found.extend(await exec_jobs())
            jobs.clear()

    # Make sure the last batch gets executed in case it doesn't exceed the thread pool size
    found.extend(await exec_jobs())

    return found


async def main():
    parser = argparse.ArgumentParser(
        prog='WebEnum',
        description="Bruteforce HTTP URIs and subdomains"
    )
    parser.add_argument('wordlist')
    parser.add_argument('path', help='Either URI or FQDN')
    parser.add_argument('-s', '--trailing-slash', action='store_true',
                        help='Append trailing slash to tested URLs')
    parser.add_argument('-d', '--depth', type=int, default=2)
    parser.add_argument('-t', '--threads', type=int, default=64,
                        help='How many threads to run. More - faster scanning.')
    parser.add_argument('-p', '--proxy')
    parser.add_argument('-j', '--json', action='store_true', help='Output scan results as JSON')

    args = parser.parse_args()

    def bailout(msg):
        if args.json:
            err = json.dumps({'error': msg})
        else:
            err = f'Error: {msg}'
        sys.exit(err)

    try:
        wordlist_file = open(args.wordlist)
    except FileNotFoundError:
        bailout(f'{args.wordlist} does not exist')
    wordlist = [ln.strip() for ln in wordlist_file.readlines()]
    wordlist = [ln for ln in wordlist if ln]

    path = urlparse(args.path)
    if path.scheme and not path.netloc:
        bailout('path is invalid')

    start_time = datetime.now()
    if not path.scheme:
        results = await scan_subdomains(args.path, wordlist, depth=args.depth, num_threads=args.threads,
                                        proxy=args.proxy, quiet=args.json)
        grouped_results = {}
        if args.json:
            for entry in results:
                for dn, addr in entry:
                    if dn not in grouped_results:
                        grouped_results[dn] = [addr]
                    else:
                        grouped_results[dn].append(addr)
        # print(grouped_results)
        # grouped_results = [(k, v) for k, v in grouped_results.items()]
        elapsed = datetime.now() - start_time
        results_json = {
            'elapsed': elapsed.total_seconds(),
            'hits': grouped_results
        }
        if not args.json:
            print()
            print(f'Hit count: {len(results)}')
            print(f'Elapsed: {str(elapsed)}')
    else:
        try:
            results: list[requests.Response] = \
                await scan_uris(args.path, wordlist, depth=args.depth,
                                trailing_slash=args.trailing_slash, num_threads=args.threads, proxy=args.proxy,
                                quiet=args.json)
        except requests.exceptions.ProxyError as exc:
            results_json = {
                'error': str(exc)
            }
            if not args.json:
                bailout(str(exc))
        else:
            elapsed = datetime.now() - start_time
            hits_json = [{
                'url': r.url,
                'status_code': r.status_code
            } for r in results]
            results_json = {
                'elapsed': elapsed.total_seconds(),
                'hits': hits_json
            }
            if not args.json:
                print()
                print(f'Hit count: {len(results)}')
                print(f'Elapsed: {str(elapsed)}')

    if args.json:
        print(json.dumps(results_json, indent=2))

if __name__ == '__main__':
    asyncio.run(main())
