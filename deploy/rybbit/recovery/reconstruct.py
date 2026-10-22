import argparse
import collections
import datetime
import gzip
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import uuid

from recovery_model import LogMatcher, Sessionizer, event_ms, identity_digest, technical_identity

TABLES = ('events', 'bot_events', 'bot_observations')
CH = ['docker', 'exec', '-i', 'clickhouse', 'clickhouse-client', '--max_threads', '1',
      '--max_memory_usage', '536870912', '--max_execution_time', '180', '--max_block_size', '4096',
      '--max_insert_block_size', '4096', '--min_insert_block_size_rows', '0',
      '--min_insert_block_size_bytes', '0', '--input_format_parallel_parsing', '0']


def run(command, input=None, timeout=240):
    stream = {'stdin':subprocess.DEVNULL} if input is None else {'input':input}
    result = subprocess.run(command, capture_output=True, timeout=timeout, **stream)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace')[-3000:])
    return result.stdout


def ch(sql, readonly=True):
    return run(CH + (['--readonly', '1'] if readonly else []) + ['--query', sql]).decode()


def pg(sql, readonly=True):
    options = '-c statement_timeout=20000' + (' -c default_transaction_read_only=on' if readonly else '')
    command = ['docker', 'exec', '-i', '-e', 'PGOPTIONS='+options, 'postgres', 'sh', '-c',
               'exec psql -X -q -A -t -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"']
    return run(command, sql.encode(), timeout=60).decode().strip()


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def ident(value):
    return '`' + value.replace('`', '``') + '`'


def utc_epoch(value):
    return int(datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())


def write_json(path, data):
    temporary = path.with_name(path.name+'.pending')
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def rows(path):
    with gzip.open(str(path), 'rt', encoding='utf-8') as handle:
        for line in handle:
            yield json.loads(line)


def table_columns(table):
    return ch("SELECT name FROM system.columns WHERE database='analytics' AND table="+quote(table)+
              ' ORDER BY position FORMAT TSV').splitlines()


def digest_table(table, site_id, start=None, end=None, exclude_site=False):
    columns = table_columns(table)
    if exclude_site:
        columns = [column for column in columns if column!='site_id']
    where = 'site_id='+str(int(site_id))
    if start is not None:
        where += ' AND timestamp>=toDateTime('+str(int(start))+') AND timestamp<toDateTime('+str(int(end))+')'
    sql = 'SELECT count() AS rows, toString(sum(cityHash64(toJSONString(tuple('+','.join(map(ident,columns))+'))))) AS checksum FROM analytics.'+ident(table)+' WHERE '+where+' FORMAT JSONEachRow'
    return json.loads(ch(sql))


def source_site(site_id):
    sql = "SELECT json_build_object('site_id',site_id,'name',name,'domain',domain,'organization_id',organization_id,'created_by',created_by,'salted',\"saltUserIds\",'row_hash',md5(row_to_json(s)::text)) FROM sites s WHERE site_id="+str(int(site_id))+';'
    result = pg(sql)
    if not result:
        raise ValueError('Source site does not exist')
    return json.loads(result)


def export_file(sql, destination):
    temporary = destination.with_name(destination.name+'.pending')
    process = subprocess.Popen(CH+['--readonly','1','--query',sql], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with gzip.open(str(temporary), 'wb', compresslevel=3) as output:
            shutil.copyfileobj(process.stdout, output, 1024*1024)
        error = process.stderr.read()
        if process.wait(timeout=240):
            raise RuntimeError(error.decode(errors='replace')[-3000:])
        temporary.chmod(0o600)
        temporary.replace(destination)
    except Exception:
        process.kill()
        raise


def save(job, manifest):
    write_json(job/'manifest.json', manifest)


def prepare(args, job):
    if (job/'manifest.json').exists():
        raise ValueError('Job already exists')
    job.mkdir(parents=True, mode=0o700, exist_ok=True)
    job.chmod(0o700)
    now = int(ch('SELECT toUnixTimestamp(now()) FORMAT TSV').strip())
    if ch('SELECT timezone() FORMAT TSV').strip()!='UTC':
        raise ValueError('Recovery expects UTC ClickHouse timestamps')
    start = utc_epoch(args.start)
    end = min(utc_epoch(args.end), now)
    source = source_site(args.source_site_id)
    if source['salted']:
        raise ValueError('This recovery requires an unsalted source site')
    if not source['organization_id'] or not source['created_by'] or end<=start:
        raise ValueError('Invalid source ownership or period')
    manifest = {'job_id':uuid.uuid4().hex, 'import_id':str(uuid.uuid4()), 'source':source,
                'start_epoch':start, 'end_epoch':end, 'fixed_epoch':utc_epoch(args.fixed_at),
                'title':args.title, 'target_public_id':secrets.token_hex(6), 'source_digests':{},
                'state':'preparing', 'tables':{}, 'method_version':1,
                'backend_image':run(['docker','inspect','backend','--format','{{.Image}}']).decode().strip(),
                'method_labels':{'ip_correlated':'оценка: IP-сопоставление', 'technical_profile':'оценка: техпрофиль',
                                 'observed_after_fix':'копия: после исправления'},
                'bot_classification':'preserved from source', 'stored_raw_ips':False}
    save(job, manifest)
    key = job/'identity.key'
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    for table in TABLES:
        fingerprint = digest_table(table, args.source_site_id, start, end)
        manifest['source_digests'][table] = fingerprint
        where = 'site_id='+str(args.source_site_id)+' AND timestamp>=toDateTime('+str(start)+') AND timestamp<toDateTime('+str(end)+')'
        export_file('SELECT * FROM analytics.'+table+' WHERE '+where+' FORMAT Native', job/(table+'.source.native.gz'))
        export_file('SELECT * FROM analytics.'+table+' WHERE '+where+' ORDER BY timestamp FORMAT JSONEachRow', job/(table+'.source.jsonl.gz'))
        save(job, manifest)
        print(json.dumps({'phase':'snapshot','table':table,'rows':fingerprint['rows']}), flush=True)
    manifest['state'] = 'prepared'
    save(job, manifest)


def enrich(args, job, manifest):
    if run(['docker','inspect','backend','--format','{{.Image}}']).decode().strip()!=manifest['backend_image']:
        raise ValueError('Backend image changed during reconstruction')
    container_dir = '/tmp/rybbit-recovery-'+manifest['job_id']
    run(['docker','exec','backend','mkdir','-p',container_dir])
    run(['docker','cp',str(pathlib.Path(__file__).with_name('enrich_proxy_logs.mjs')),'backend:'+container_dir+'/enrich.mjs'])
    run(['docker','cp',str(job/'identity.key'),'backend:'+container_dir+'/identity.key'])
    command = ['docker','exec','-i','backend','node',container_dir+'/enrich.mjs',container_dir+'/identity.key',args.proxy_ip,str(manifest['source']['site_id'])]
    process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    import threading
    errors = []
    def feed():
        try:
            with gzip.open(args.raw_logs,'rb') as source:
                shutil.copyfileobj(source,process.stdin,1024*1024)
            process.stdin.close()
        except Exception as error:
            errors.append(type(error).__name__)
    feeder = threading.Thread(target=feed,daemon=True)
    feeder.start()
    count = 0
    with gzip.open(str(job/'enriched-logs.jsonl.gz'),'wb',compresslevel=3) as output:
        for line in process.stdout:
            record = json.loads(line)
            if 'log_id' in record:
                output.write(line)
                count += 1
    feeder.join(timeout=30)
    error = process.stderr.read()
    if process.wait(timeout=60) or errors:
        raise RuntimeError('Log enrichment failed: '+error.decode(errors='replace')[-2000:])
    if count<20:
        raise ValueError('Insufficient proxy records')
    manifest['enriched_log_count'] = count
    manifest['state'] = 'enriched'
    save(job,manifest)
    print(json.dumps({'phase':'enriched','records':count}),flush=True)


def build(job, manifest):
    if manifest.get('state')!='enriched':
        raise ValueError('Enrichment must complete first')
    logs = list(rows(job/'enriched-logs.jsonl.gz'))
    matcher = LogMatcher(logs)
    first = min(row['start_ms'] for row in logs)
    last = max(row['end_ms'] for row in logs)
    fixed = manifest['fixed_epoch']*1000
    samples = [row for row in rows(job/'events.source.jsonl.gz') if fixed+5000<=event_ms(row)<last-5000]
    manifest['calibration'] = matcher.calibrate(samples)
    print(json.dumps({'phase':'calibrated',**manifest['calibration']}),flush=True)
    key = (job/'identity.key').read_bytes()
    for table in TABLES:
        counters = collections.Counter()
        sessions = Sessionizer(key)
        with gzip.open(str(job/(table+'.estimated.jsonl.gz')),'wt',encoding='utf-8',compresslevel=3) as output:
            for event in rows(job/(table+'.source.jsonl.gz')):
                timestamp = event_ms(event)
                log = None
                if timestamp>=fixed:
                    identity = identity_digest(key,'native\0'+event['user_id'])
                    method = 'observed_after_fix'
                elif first-3000<=timestamp<=last+3000:
                    log, status = matcher.match(event)
                    counters['matching_'+status] += 1
                    if log:
                        identity = log['target_identity']
                        method = 'ip_correlated'
                    else:
                        identity = technical_identity(key,event)
                        method = 'technical_profile'
                else:
                    identity = technical_identity(key,event)
                    method = 'technical_profile'
                event['site_id'] = 0
                event['user_id'] = identity
                event['session_id'] = 'bot:'+identity if table=='bot_events' else sessions.session(identity,timestamp)
                if log:
                    for field,value in log['geo'].items():
                        if field in event:
                            event[field] = value
                if 'ip' in event:
                    event['ip'] = None
                if table=='events':
                    event['import_id'] = manifest['import_id']
                    event['tag'] = manifest['method_labels'][method]
                output.write(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n')
                counters[method] += 1
                counters['rows'] += 1
        if counters['rows']!=manifest['source_digests'][table]['rows']:
            raise ValueError('Snapshot event count changed')
        manifest['tables'][table] = dict(counters)
        save(job,manifest)
        print(json.dumps({'phase':'estimated','table':table,**dict(counters)}),flush=True)
    manifest['state'] = 'built'
    save(job,manifest)


def assert_source_unchanged(manifest):
    source = manifest['source']
    if run(['docker','inspect','backend','--format','{{.Image}}']).decode().strip()!=manifest['backend_image']:
        raise ValueError('Backend image changed during reconstruction')
    if source_site(source['site_id'])['row_hash']!=source['row_hash']:
        raise ValueError('Source site settings changed during reconstruction')
    for table in TABLES:
        current = digest_table(table,source['site_id'],manifest['start_epoch'],manifest['end_epoch'])
        if current!=manifest['source_digests'][table]:
            raise ValueError('Source history changed: '+table)


def create_target(job, manifest):
    if manifest.get('target_site_id'):
        return manifest['target_site_id']
    public_id = manifest['target_public_id']
    source_id = int(manifest['source']['site_id'])
    sql = "BEGIN; INSERT INTO sites (name,domain,created_by,organization_id,public,id,\"saltUserIds\",\"blockBots\",\"trackIp\",\"trackInitialPageView\",\"trackSpaNavigation\",\"trackOutbound\",\"sessionReplay\",\"webVitals\",\"trackErrors\",\"trackButtonClicks\",\"trackCopy\",\"trackFormInteractions\",first_party_proxy,tags) SELECT "+quote(manifest['title'])+",domain,created_by,organization_id,false,"+quote(public_id)+",false,\"blockBots\",false,false,false,false,false,false,false,false,false,false,true,'[\"оценка\"]'::jsonb FROM sites WHERE site_id="+str(source_id)+" AND NOT EXISTS (SELECT 1 FROM sites WHERE id="+quote(public_id)+"); SELECT json_build_object('site_id',site_id,'id',id,'name',name,'public',public) FROM sites WHERE id="+quote(public_id)+"; INSERT INTO team_site_access (team_id,site_id) SELECT team_id,(SELECT site_id FROM sites WHERE id="+quote(public_id)+") FROM team_site_access WHERE site_id="+str(source_id)+"; INSERT INTO member_site_access (member_id,site_id,created_by) SELECT member_id,(SELECT site_id FROM sites WHERE id="+quote(public_id)+") ,created_by FROM member_site_access WHERE site_id="+str(source_id)+"; COMMIT;"
    target = json.loads(pg(sql,readonly=False))
    if target['site_id']==source_id or target['public'] or target['name']!=manifest['title']:
        raise ValueError('Unsafe target site')
    manifest['target_site_id'] = target['site_id']
    manifest['target'] = target
    save(job,manifest)
    return target['site_id']


def stage(job, manifest):
    for table in TABLES:
        stage_name = 'recovery_'+manifest['job_id']+'_'+table
        if manifest.get('staging',{}).get(table):
            continue
        ch('CREATE TABLE IF NOT EXISTS analytics.'+ident(stage_name)+' AS analytics.'+ident(table),readonly=False)
        if digest_table(stage_name,0)['rows']:
            raise ValueError('Unverified staging table already contains rows')
        if manifest['source_digests'][table]['rows']:
            process = subprocess.Popen(CH+['--query','INSERT INTO analytics.'+ident(stage_name)+' FORMAT JSONEachRow'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                with gzip.open(str(job/(table+'.estimated.jsonl.gz')),'rb') as source:
                    shutil.copyfileobj(source,process.stdin,1024*1024)
                process.stdin.close()
            except BrokenPipeError:
                pass
            error = process.stderr.read()
            if process.wait(timeout=240):
                raise RuntimeError(error.decode(errors='replace')[-3000:])
        fingerprint = digest_table(stage_name,0,exclude_site=True)
        if fingerprint['rows']!=manifest['source_digests'][table]['rows']:
            raise ValueError('Staging count mismatch')
        manifest.setdefault('staging',{})[table] = {'table':stage_name,**fingerprint}
        save(job,manifest)
        print(json.dumps({'phase':'staged','table':table,'rows':fingerprint['rows']}),flush=True)


def apply(job, manifest):
    if manifest.get('state') not in ('built','publishing'):
        raise ValueError('Build must complete first')
    assert_source_unchanged(manifest)
    stage(job,manifest)
    target_id = create_target(job,manifest)
    if target_id==manifest['source']['site_id']:
        raise ValueError('Refusing to write source site')
    manifest['state'] = 'publishing'
    save(job,manifest)
    for table in TABLES:
        expected = {key:value for key,value in manifest['staging'][table].items() if key in ('rows','checksum')}
        existing = digest_table(table,target_id,exclude_site=True)
        if existing==expected:
            continue
        if existing['rows']:
            raise ValueError('Target has unexpected existing events; refusing duplicate insert')
        columns = table_columns(table)
        selection = ['toUInt16('+str(target_id)+')' if column=='site_id' else ident(column) for column in columns]
        sql = 'INSERT INTO analytics.'+ident(table)+' ('+','.join(map(ident,columns))+') SELECT '+','.join(selection)+' FROM analytics.'+ident(manifest['staging'][table]['table'])+' WHERE site_id=0'
        ch(sql,readonly=False)
        actual = digest_table(table,target_id,exclude_site=True)
        if actual!=expected:
            raise ValueError('Published copy checksum mismatch')
        print(json.dumps({'phase':'published','table':table,'rows':actual['rows']}),flush=True)
    assert_source_unchanged(manifest)
    manifest['state'] = 'complete'
    manifest['source_unchanged'] = True
    save(job,manifest)
    print(json.dumps({'phase':'complete','target_site_id':target_id,'source_unchanged':True,'title':manifest['title']},ensure_ascii=False),flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('prepare','enrich','build','apply'))
    parser.add_argument('--job-dir',required=True)
    parser.add_argument('--source-site-id',type=int)
    parser.add_argument('--start')
    parser.add_argument('--end')
    parser.add_argument('--fixed-at')
    parser.add_argument('--title')
    parser.add_argument('--raw-logs')
    parser.add_argument('--proxy-ip')
    args = parser.parse_args()
    os.umask(0o077)
    job = pathlib.Path(args.job_dir).resolve()
    if args.action=='prepare':
        prepare(args,job)
        return
    manifest = json.loads((job/'manifest.json').read_text())
    if args.action=='enrich':
        enrich(args,job,manifest)
    elif args.action=='build':
        build(job,manifest)
    else:
        apply(job,manifest)


if __name__=='__main__':
    main()
