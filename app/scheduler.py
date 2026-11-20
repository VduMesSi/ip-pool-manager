import asyncio
import csv
import ipaddress
import logging
import random
import socket
import subprocess
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .config import DATA_DIR, CFST_BIN, SCAN_TIMEOUT
from .quality import QualityStore

log=logging.getLogger("ip-pool.scheduler")
TZ=ZoneInfo("Asia/Taipei")
RUN_TIMES=((7,30),(13,30),(19,30))
TOTAL_TARGET=3000
BATCH_SIZE=300
CONCURRENCY=20
PING_COUNT=4
MAX_LATENCY=120
BATCH_PAUSE_SECONDS=300
CYCLE_LOCK=asyncio.Lock()

def _read_source(path, version):
    networks=[]
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        value=raw.strip()
        if not value or value.startswith("#"): continue
        net=ipaddress.ip_network(value,strict=False)
        if net.version != version: raise ValueError(f"wrong IP family in {path}: {value}")
        networks.append(net)
    return list(ipaddress.collapse_addresses(networks)) if networks else []

def _random_source_ips(networks, count, excluded):
    if not networks or count <= 0: return []
    ranges=[]; ends=[]; total=0
    for net in networks:
        ranges.append((int(net.network_address),net.num_addresses))
        total+=net.num_addresses; ends.append(total)
    chosen=set(); attempts=0; limit=max(1000,count*40)
    while len(chosen)<count and attempts<limit and len(chosen)<total:
        offset=random.randrange(total); attempts+=1
        idx=0
        while offset>=ends[idx]: idx+=1
        previous=ends[idx-1] if idx else 0
        ip=str(ipaddress.ip_address(ranges[idx][0]+offset-previous))
        if ip not in excluded: chosen.add(ip)
    if len(chosen)<count and total<=100000:
        for net in networks:
            for addr in net:
                ip=str(addr)
                if ip not in excluded: chosen.add(ip)
                if len(chosen)>=count: break
            if len(chosen)>=count: break
    return list(chosen)[:count]

def _source_candidates(engine, quality, count):
    networks=_read_source(engine.source,engine.version)
    excluded=set(); result=[]
    weighted=quality.active(engine.family)+[
        (x["ip"],x.get("latency_ms") or 999.0) for x in engine.get_candidates()
    ]
    random.shuffle(weighted)
    # Reserve up to 20% for known-good addresses; remaining slots explore the source ranges.
    for ip,_ in weighted:
        if ip not in excluded:
            excluded.add(ip); result.append(ip)
            if len(result)>=min(count//5,count): break
    result.extend(_random_source_ips(networks,count-len(result),excluded))
    return result[:count]

def _internet_ok():
    """Pass on >=2/3 TCP/443 targets in round 1; otherwise retry up to two more rounds."""
    hosts=("www.baidu.com","www.microsoft.com","www.qq.com")
    for round_no in (1,2,3):
        successes=0
        for host in hosts:
            started=time.monotonic()
            try:
                with socket.create_connection((host,443),timeout=2.0):
                    successes+=1
                    log.info("WAN check round %d: %s:443 reachable (%.2fs)",
                             round_no,host,time.monotonic()-started)
            except OSError as exc:
                log.warning("WAN check round %d: %s:443 failed after %.2fs: %s",
                            round_no,host,time.monotonic()-started,exc)
        log.info("WAN check round %d summary: %d/3 targets reachable",
                 round_no,successes)
        if successes>=2:
            log.info("WAN check passed on round %d",round_no)
            return True
        if round_no<3:
            log.warning("WAN check round %d did not meet 2/3; retrying in 3 seconds",
                        round_no)
            time.sleep(3)
    log.error("WAN check failed: fewer than 2/3 targets reachable in all 3 rounds")
    return False

def _write_csv_atomic(path,header,rows):
    temp=path.with_name(f".{path.name}.tmp")
    try:
        with temp.open("w",encoding="utf-8-sig",newline="") as f:
            writer=csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)

def _parse_csv(path,family):
    with path.open("r",encoding="utf-8-sig",newline="") as f: rows=list(csv.reader(f))
    if not rows or len(rows[0])<5 or rows[0][4].strip()!="平均延迟":
        raise RuntimeError(f"unexpected CFST CSV format: {path}")
    out={}
    for row in rows[1:]:
        if len(row)<5: continue
        try:
            addr=ipaddress.ip_address(row[0].strip())
            if addr.version!=(4 if family=="ipv4" else 6): continue
            latency=float(row[4]); loss=float(row[3].strip().rstrip("%") or 0)
            if 0<latency<=60000:
                key=str(addr)
                if key not in out or latency<out[key][0]:
                    out[key]=(latency,loss,row)
        except (ValueError,TypeError): continue
    return rows[0],out

def _run_batch(engine,ips,batch_no,quality,day):
    if not ips: return 0
    if not engine.scan_lock.acquire(blocking=False):
        raise RuntimeError(f"{engine.family} scan already running; batch skipped")
    try:
        base=engine.base
        input_path=base/f".scheduled_{batch_no}.txt"
        output_path=base/f".scheduled_{batch_no}.csv"
        input_path.write_text("\n".join(ips)+"\n",encoding="utf-8")
        output_path.unlink(missing_ok=True)
        cmd=[str(CFST_BIN),"-f",str(input_path),"-o",str(output_path),
             "-n",str(CONCURRENCY),"-t",str(PING_COUNT),"-tl",str(MAX_LATENCY),
             "-tlr","0","-dd","-p","0"]
        started=time.monotonic()
        proc=subprocess.run(cmd,cwd=str(base),capture_output=True,timeout=SCAN_TIMEOUT,check=False)
        if proc.returncode!=0:
            raise RuntimeError(f"CFST failed rc={proc.returncode}: {proc.stderr.decode('utf-8','replace')[-1000:]}")
        if not output_path.is_file(): raise RuntimeError("CFST output file missing")
        header,results=_parse_csv(output_path,engine.family)
        for ip,(lat,loss,_) in results.items():
            quality.record(ip,engine.family,day,lat,loss)
        existing={}
        if engine.result.is_file():
            try:
                _,existing=_parse_csv(engine.result,engine.family)
            except (OSError,RuntimeError):
                log.exception("could not read previous %s result CSV; retaining current batch only",engine.family)
        for ip,item in results.items():
            if ip not in existing or item[0]<existing[ip][0]:
                existing[ip]=item
        rows=(row for _,(_,_,row) in sorted(existing.items(),key=lambda x:x[1][0]))
        _write_csv_atomic(engine.result,header,rows)
        log.info("%s batch %d: targets=%d results=%d duration=%.1fs",
                 engine.family,batch_no,len(ips),len(results),time.monotonic()-started)
        return len(results)
    finally:
        engine.scan_lock.release()

def _append_permanent_candidates(engine,quality):
    header=["IP 地址","已发送","已接收","丢包率","平均延迟","下载速度(MB/s)","地区码"]
    existing={}
    if engine.result.is_file():
        try:
            header,existing=_parse_csv(engine.result,engine.family)
        except (OSError,RuntimeError):
            log.exception("could not read %s result CSV while appending permanent candidates",engine.family)
    for ip,lat in quality.active(engine.family):
        if ip not in existing:
            existing[ip]=(lat,0.0,[ip,"","","",f"{lat:.2f}","",""])
    rows=(row for _,(_,_,row) in sorted(existing.items(),key=lambda x:x[1][0]))
    _write_csv_atomic(engine.result,header,rows)

async def run_full_cycle(engines):
    if CYCLE_LOCK.locked(): return {"ok":False,"reason":"cycle_already_running"}
    async with CYCLE_LOCK:
        started=time.monotonic()
        quality=QualityStore(DATA_DIR/"quality"/"ip_quality.sqlite3")
        day=datetime.now(TZ).date()
        candidates={f:_source_candidates(engines[f],quality,TOTAL_TARGET//2) for f in ("ipv4","ipv6")}
        # Reallocate a shortfall to the other family while keeping the combined cap.
        for family in ("ipv4","ipv6"):
            if sum(map(len,candidates.values()))>=TOTAL_TARGET: break
            need=TOTAL_TARGET-sum(map(len,candidates.values()))
            more=_source_candidates(engines[family],quality,len(candidates[family])+need)
            seen=set(candidates[family])
            candidates[family].extend(ip for ip in more if ip not in seen)
            candidates[family]=candidates[family][:TOTAL_TARGET-sum(
                len(v) for k,v in candidates.items() if k!=family)]
        queues={f:[v[i:i+BATCH_SIZE] for i in range(0,len(v),BATCH_SIZE)] for f,v in candidates.items()}
        schedule=[]
        for i in range(max(len(queues["ipv4"]),len(queues["ipv6"]))):
            for family in ("ipv4","ipv6"):
                if i<len(queues[family]): schedule.append((family,queues[family][i]))
        if not schedule: return {"ok":False,"reason":"no_scan_targets"}
        total=sum(len(batch) for _,batch in schedule)
        log.info("scan cycle started: total=%d ipv4=%d ipv6=%d batches=%d",
                 total,len(candidates["ipv4"]),len(candidates["ipv6"]),len(schedule))
        completed=[]
        for index,(family,ips) in enumerate(schedule,1):
            if not _internet_ok():
                log.error("cycle aborted before batch %d: WAN check failed",index)
                return {"ok":False,"reason":"outbound_connectivity_lost","completed_batches":completed}
            count=await asyncio.to_thread(_run_batch,engines[family],ips,index,quality,day)
            completed.append({"family":family,"targets":len(ips),"results":count})
            if index<len(schedule): await asyncio.sleep(BATCH_PAUSE_SECONDS)
        for family in ("ipv4","ipv6"):
            _append_permanent_candidates(engines[family],quality)
            refreshed=await asyncio.to_thread(engines[family].refresh)
            log.info("%s post-cycle refresh: %s",family,refreshed)
        return {"ok":True,"batches":completed,"total_targets":total,
                "duration_seconds":round(time.monotonic()-started,1)}

def _next_run(now):
    for hour,minute in RUN_TIMES:
        candidate=now.replace(hour=hour,minute=minute,second=0,microsecond=0)
        if candidate>now: return candidate
    tomorrow=now+timedelta(days=1); hour,minute=RUN_TIMES[0]
    return tomorrow.replace(hour=hour,minute=minute,second=0,microsecond=0)

async def _scheduler_loop(engines):
    while True:
        now=datetime.now(TZ); nxt=_next_run(now)
        log.info("next scan cycle at %s Asia/Taipei",nxt.isoformat(timespec="minutes"))
        await asyncio.sleep(max(1,(nxt-now).total_seconds()))
        try: await run_full_cycle(engines)
        except Exception: log.exception("scheduled scan cycle failed; scheduler remains active")

def start_scheduler(engines):
    return [asyncio.create_task(_scheduler_loop(engines),name="ip-pool-batched-scheduler")]

async def stop_scheduler(tasks):
    for task in tasks: task.cancel()
    await asyncio.gather(*tasks,return_exceptions=True)
