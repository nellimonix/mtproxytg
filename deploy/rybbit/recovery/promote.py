import argparse
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import uuid

from recovery_model import event_ms
from reconstruct import (CH, assert_source_unchanged, ch, digest_table, export_file, ident,
                         rows, save, source_site, table_columns, utc_epoch)
from refine import LABELS, queries, target_guard

MUTABLE = ('user_id','session_id','country','region','city','lat','lon','timezone',
           'asn','asn_org','is_datacenter_asn','tag','import_id')


def approved_pair(original, recovered, start, end):
    if recovered.get('tag')!=LABELS['ip_correlated']:
        return False
    if not start*1000<=event_ms(original)<end*1000:
        return False
    fields = (set(original)|set(recovered))-set(MUTABLE)-{'site_id'}
    if any(original.get(field)!=recovered.get(field) for field in fields):
        raise ValueError('Recovery changes an immutable event field')
    if len(recovered.get('user_id',''))!=12 or recovered.get('ip')!=original.get('ip'):
        raise ValueError('Invalid confirmed identity or raw IP change')
    return True


def key_expression(columns):
    fixed = [column for column in columns if column not in MUTABLE]
    if 'site_id' not in fixed or 'timestamp_ms' not in fixed:
        raise ValueError('Incomplete immutable event key')
    return 'hex(SHA256(toJSONString(tuple('+','.join(map(ident,fixed))+'))))'


def selection(manifest):
    return ('site_id='+str(manifest['site_id'])+' AND timestamp>=toDateTime('+str(manifest['start_epoch'])+
            ') AND timestamp<toDateTime('+str(manifest['end_epoch'])+
            ") AND joinGet('analytics."+manifest['new_map']+"','matched',"+manifest['key_expression']+')=1')


def fingerprint(table, columns, where):
    payload = 'toJSONString(tuple('+','.join(map(ident,columns))+'))'
    return queries('WITH '+payload+' AS payload SELECT count() AS rows,'+
                   'toString(sum(cityHash64(payload))) AS checksum,'+
                   'toString(sum(sipHash64(payload))) AS checksum2 FROM analytics.'+ident(table)+' WHERE '+where)[0]


def load_file(table, path, format_name):
    process = subprocess.Popen(CH+['--query','INSERT INTO analytics.'+ident(table)+' FORMAT '+format_name],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        with gzip.open(path,'rb') as source:
            shutil.copyfileobj(source,process.stdin,1024*1024)
        process.stdin.close()
    except BrokenPipeError:
        pass
    error = process.stderr.read()
    if process.wait(timeout=240):
        raise RuntimeError(error.decode(errors='replace')[-2000:])


def update_sql(table, lookup, manifest):
    assignments = [ident(column)+"=joinGet('analytics."+lookup+"','"+column+"',"+
                   manifest['key_expression']+')' for column in MUTABLE]
    return ('ALTER TABLE analytics.'+ident(table)+' UPDATE '+','.join(assignments)+' WHERE '+selection(manifest)+
            ' SETTINGS mutations_sync=2')


def protected_where(manifest):
    return ('timestamp>=toStartOfMonth(toDateTime('+str(manifest['start_epoch'])+')) AND timestamp<toDateTime('+
            str(manifest['cutoff_epoch'])+') AND NOT ('+selection(manifest)+')')


def daily(table, manifest, end=None):
    return queries("SELECT toString(toDate(timestamp,'Europe/Moscow')) AS date,count() AS events,"+
                   "countIf(type='pageview') AS pageviews,uniqExact(user_id) AS users,uniqExact(session_id) AS sessions "+
                   'FROM analytics.'+ident(table)+' WHERE site_id='+str(manifest['site_id'])+
                   ' AND timestamp>=toDateTime('+str(manifest['start_epoch'])+') AND timestamp<toDateTime('+
                   str(end if end is not None else manifest['cutoff_epoch'])+') GROUP BY date ORDER BY date')


def check_settings(manifest):
    if source_site(manifest['site_id'])['row_hash']!=manifest['source_row_hash']:
        raise ValueError('Production site settings changed')
    if table_columns('events')!=manifest['columns']:
        raise ValueError('Production event schema changed')


def prepare(args, job):
    if (job/'manifest.json').exists():
        raise ValueError('Promotion job already exists')
    reference_job = pathlib.Path(args.reference_job_dir).resolve()
    reference = json.loads((reference_job/'manifest.json').read_text())
    if reference['state']!='complete' or reference.get('method_version')!=2:
        raise ValueError('A completed conservative reconstruction is required')
    if (reference['validation']['ip_holdout'].get('holdout_errors',0)
            or reference['validation']['ip_holdout'].get('holdout_cases',0)<200):
        raise ValueError('Reference IP validation has errors')
    assert_source_unchanged(reference)
    target_guard(reference)
    current_copy = digest_table('events',reference['target_site_id'],exclude_site=True)
    if current_copy!={key:reference['staging']['events'][key] for key in ('rows','checksum')}:
        raise ValueError('Reference copy changed')
    start = utc_epoch(args.start)
    end = min(utc_epoch(args.end),reference['fixed_epoch'])
    if not reference['affected_epoch']<=start<end<=reference['end_epoch']:
        raise ValueError('Promotion is outside the approved recovery interval')
    job.mkdir(parents=True,mode=0o700,exist_ok=True)
    job.chmod(0o700)
    if shutil.disk_usage(job).free<2*1024**3:
        raise ValueError('Insufficient free space for verified backups')
    token = uuid.uuid4().hex
    manifest = {'job_id':token,'import_id':str(uuid.uuid4()),'site_id':reference['source']['site_id'],
                'copy_site_id':reference['target_site_id'],'reference_job_id':reference['job_id'],
                'start_epoch':start,'end_epoch':end,'comparison_end_epoch':reference['end_epoch'],
                'cutoff_epoch':int(ch('SELECT toUnixTimestamp(now())-300 FORMAT TSV').strip()),
                'source_row_hash':reference['source']['row_hash'],'state':'preparing',
                'original_table':'promotion_'+token+'_original','updated_table':'promotion_'+token+'_updated',
                'preview_table':'promotion_'+token+'_preview','old_map':'promotion_'+token+'_old_map',
                'new_map':'promotion_'+token+'_new_map','columns':table_columns('events')}
    manifest['key_expression'] = key_expression(manifest['columns'])
    save(job,manifest)
    count = 0
    with gzip.open(job/'original.jsonl.gz','wt',encoding='utf-8') as old_output, gzip.open(job/'updated.jsonl.gz','wt',encoding='utf-8') as new_output:
        for original,recovered in zip(rows(reference_job/'events.source.jsonl.gz'),rows(reference_job/'events.estimated.jsonl.gz'),strict=True):
            if not approved_pair(original,recovered,start,end):
                continue
            recovered['site_id'] = manifest['site_id']
            recovered['import_id'] = manifest['import_id']
            old_output.write(json.dumps(original,ensure_ascii=False,separators=(',',':'))+'\n')
            new_output.write(json.dumps(recovered,ensure_ascii=False,separators=(',',':'))+'\n')
            count += 1
    if not count:
        raise ValueError('No confirmed events are eligible for promotion')
    manifest['confirmed_rows'] = count
    for field,filename in [('original_table','original.jsonl.gz'),('updated_table','updated.jsonl.gz')]:
        ch('CREATE TABLE analytics.'+ident(manifest[field])+' AS analytics.events',readonly=False)
        load_file(manifest[field],job/filename,'JSONEachRow')
    fixed = [column for column in manifest['columns'] if column not in MUTABLE]
    old_core = fingerprint(manifest['original_table'],fixed,'1')
    if old_core['rows']!=count or fingerprint(manifest['updated_table'],fixed,'1')!=old_core:
        raise ValueError('Promotion changes immutable event contents or multiplicity')
    for field,table_field in [('old_map','original_table'),('new_map','updated_table')]:
        key = manifest['key_expression']
        variants = queries('SELECT count() AS conflicts FROM (SELECT '+key+' AS event_key,uniqExact(toJSONString(tuple('+
                           ','.join(map(ident,MUTABLE))+'))) AS variants FROM analytics.'+ident(manifest[table_field])+
                           ' GROUP BY event_key HAVING variants!=1)')[0]['conflicts']
        if variants:
            raise ValueError('An event key has conflicting recovery values')
        ch('CREATE TABLE analytics.'+ident(manifest[field])+' ENGINE=Join(ANY,LEFT,event_key) AS SELECT '+key+
           ' AS event_key,toUInt8(1) AS matched,'+','.join(map(ident,MUTABLE))+' FROM analytics.'+ident(manifest[table_field]),readonly=False)
    manifest['original_digest'] = fingerprint(manifest['original_table'],manifest['columns'],'1')
    manifest['updated_digest'] = fingerprint(manifest['updated_table'],manifest['columns'],'1')
    if fingerprint('events',manifest['columns'],selection(manifest))!=manifest['original_digest']:
        raise ValueError('Production events do not match the approved original records exactly')
    window = ('site_id='+str(manifest['site_id'])+' AND timestamp>=toDateTime('+str(start)+
              ') AND timestamp<toDateTime('+str(manifest['cutoff_epoch'])+')')
    manifest['window_where'] = window
    export_file('SELECT * FROM analytics.events WHERE '+window+' FORMAT Native',job/'production-window.native.gz')
    export_file('SELECT * FROM analytics.events WHERE '+selection(manifest)+' FORMAT Native',job/'approved-original.native.gz')
    manifest['backup_sha256'] = {}
    for filename in ('production-window.native.gz','approved-original.native.gz'):
        with (job/filename).open('rb') as handle:
            manifest['backup_sha256'][filename] = hashlib.file_digest(handle,'sha256').hexdigest()
    manifest['window_digest'] = fingerprint('events',manifest['columns'],window)
    manifest['protected_digest'] = fingerprint('events',manifest['columns'],protected_where(manifest))
    manifest['bot_digests'] = {table:fingerprint(table,table_columns(table),window) for table in ('bot_events','bot_observations')}
    manifest['daily_before'] = daily('events',manifest)
    manifest['daily_comparison_before'] = daily('events',manifest,manifest['comparison_end_epoch'])
    save(job,manifest)
    print(json.dumps({'phase':'backup_complete','confirmed_events':count,'window_events':manifest['window_digest']['rows']}),flush=True)
    ch('CREATE TABLE analytics.'+ident(manifest['preview_table'])+' AS analytics.events',readonly=False)
    load_file(manifest['preview_table'],job/'production-window.native.gz','Native')
    if fingerprint(manifest['preview_table'],manifest['columns'],'1')!=manifest['window_digest']:
        raise ValueError('Native backup failed round-trip verification')
    preview_unselected = fingerprint(manifest['preview_table'],manifest['columns'],'NOT ('+selection(manifest)+')')
    ch(update_sql(manifest['preview_table'],manifest['new_map'],manifest),readonly=False)
    if fingerprint(manifest['preview_table'],manifest['columns'],selection(manifest))!=manifest['updated_digest']:
        raise ValueError('Preview update does not match confirmed recovery')
    if fingerprint(manifest['preview_table'],manifest['columns'],'NOT ('+selection(manifest)+')')!=preview_unselected:
        raise ValueError('Preview update changed unselected events')
    preview_daily = daily(manifest['preview_table'],manifest)
    before_totals = [(row['date'],row['events'],row['pageviews']) for row in manifest['daily_before']]
    if [(row['date'],row['events'],row['pageviews']) for row in preview_daily]!=before_totals:
        raise ValueError('Preview update changed event or pageview counts')
    ch(update_sql(manifest['preview_table'],manifest['old_map'],manifest),readonly=False)
    if fingerprint(manifest['preview_table'],manifest['columns'],'1')!=manifest['window_digest']:
        raise ValueError('Rollback preview failed')
    manifest['dry_run_passed'] = True
    manifest['rollback_test_passed'] = True
    manifest['state'] = 'ready'
    save(job,manifest)
    print(json.dumps({'phase':'ready','confirmed_events':count,'dry_run_passed':True,'rollback_test_passed':True}),flush=True)


def verify(job, manifest):
    check_settings(manifest)
    if fingerprint('events',manifest['columns'],selection(manifest))!=manifest['updated_digest']:
        raise ValueError('Production recovery does not match approved records')
    if fingerprint('events',manifest['columns'],protected_where(manifest))!=manifest['protected_digest']:
        raise ValueError('Events outside the approved selection changed')
    for table,expected in manifest['bot_digests'].items():
        if fingerprint(table,table_columns(table),manifest['window_where'])!=expected:
            raise ValueError('Bot history changed')
    after = daily('events',manifest)
    if [(row['date'],row['events'],row['pageviews']) for row in after]!=[(row['date'],row['events'],row['pageviews']) for row in manifest['daily_before']]:
        raise ValueError('Production event or pageview counts changed')
    core = [column for column in manifest['columns'] if column not in ('site_id','tag','import_id')]
    interval = 'timestamp>=toDateTime('+str(manifest['start_epoch'])+') AND timestamp<toDateTime('+str(manifest['comparison_end_epoch'])+')'
    production = fingerprint('events',core,'site_id='+str(manifest['site_id'])+' AND '+interval)
    copy = fingerprint('events',core,'site_id='+str(manifest['copy_site_id'])+' AND '+interval)
    if production!=copy:
        raise ValueError('Production differs from conservative copy in the common interval')
    report = {'site_id':manifest['site_id'],'confirmed_events_updated':manifest['confirmed_rows'],
              'backup_available':True,'native_backup_round_trip_verified':True,'rollback_test_passed':True,
              'unselected_october_events_unchanged':True,'protected_events_checked':manifest['protected_digest']['rows'],
              'bot_history_unchanged':True,'event_counts_unchanged':True,'pageview_counts_unchanged':True,
              'matches_conservative_copy':True,'settings_unchanged':True,'cutoff_epoch':manifest['cutoff_epoch'],
              'comparison_end_epoch':manifest['comparison_end_epoch'],'daily_before':manifest['daily_before'],
              'daily_after':after,'daily_comparison_before':manifest['daily_comparison_before'],
              'daily_comparison_after':daily('events',manifest,manifest['comparison_end_epoch'])}
    report['recent_tracking'] = queries("SELECT count() AS events,uniqExact(user_id) AS users,countIf(country!=char(0,0)) AS events_with_country FROM analytics.events WHERE site_id="+str(manifest['site_id'])+' AND timestamp>=now()-INTERVAL 5 MINUTE')[0]
    path = job/'result.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    path.chmod(0o600)
    manifest['state'] = 'complete'
    save(job,manifest)
    print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)


def apply(job, manifest):
    if manifest['state'] not in ('ready','applying','complete') or not manifest.get('dry_run_passed') or not manifest.get('rollback_test_passed'):
        raise ValueError('Verified backups, preview and rollback test are required')
    check_settings(manifest)
    current = fingerprint('events',manifest['columns'],selection(manifest))
    if current==manifest['updated_digest']:
        verify(job,manifest)
        return
    if current!=manifest['original_digest']:
        raise ValueError('Approved source events changed before promotion')
    if fingerprint('events',manifest['columns'],protected_where(manifest))!=manifest['protected_digest']:
        raise ValueError('Protected history changed before promotion')
    for filename,expected in manifest['backup_sha256'].items():
        with (job/filename).open('rb') as handle:
            if hashlib.file_digest(handle,'sha256').hexdigest()!=expected:
                raise ValueError('Backup checksum mismatch')
    manifest['state'] = 'applying'
    save(job,manifest)
    ch(update_sql('events',manifest['new_map'],manifest),readonly=False)
    verify(job,manifest)


def rollback(job, manifest):
    check_settings(manifest)
    ch(update_sql('events',manifest['old_map'],manifest),readonly=False)
    if fingerprint('events',manifest['columns'],selection(manifest))!=manifest['original_digest']:
        raise ValueError('Rollback verification failed')
    manifest['state'] = 'rolled_back'
    save(job,manifest)
    print(json.dumps({'phase':'rolled_back','events_restored':manifest['confirmed_rows']}),flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('prepare','apply','verify','rollback'))
    parser.add_argument('--job-dir',required=True)
    parser.add_argument('--reference-job-dir')
    parser.add_argument('--start')
    parser.add_argument('--end')
    args = parser.parse_args()
    os.umask(0o077)
    job = pathlib.Path(args.job_dir).resolve()
    if args.action=='prepare':
        prepare(args,job)
    else:
        manifest = json.loads((job/'manifest.json').read_text())
        {'apply':apply,'verify':verify,'rollback':rollback}[args.action](job,manifest)


if __name__=='__main__':
    main()
