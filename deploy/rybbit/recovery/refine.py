import argparse
import collections
import datetime
import json
import os
import pathlib
import uuid

from recovery_model import ConservativeBridge, LogMatcher, PROFILE_FIELDS, Sessionizer, event_ms
from reconstruct import (TABLES, assert_source_unchanged, ch, digest_table, export_file, ident,
                         pg, quote, rows, save, source_site, stage, table_columns, utc_epoch)

LABELS = {'before_update':'копия: до обновления', 'after_fix':'копия: после исправления',
          'ip_correlated':'оценка: IP-сопоставление', 'validated_bridge':'оценка: подтверждённая связь',
          'unresolved':'не восстановлено: нет надёжной связи'}


def queries(sql):
    return [json.loads(line) for line in ch(sql+' FORMAT JSONEachRow').splitlines()]


def target_guard(manifest):
    target = source_site(manifest['target_site_id'])
    source = manifest['source']
    settings = json.loads(pg("SELECT json_build_object('public',public,'row_hash',md5(row_to_json(s)::text)) FROM sites s WHERE site_id="+str(target['site_id'])))
    if (target['site_id']==source['site_id'] or target['organization_id']!=source['organization_id']
            or target['created_by']!=source['created_by'] or settings['public'] or 'оценка' not in target['name']):
        raise ValueError('Target is not the private reconstruction copy')
    if manifest.get('target_row_hash') and settings['row_hash']!=manifest['target_row_hash']:
        raise ValueError('Target settings changed')
    return settings['row_hash']


def prepare(args, job):
    previous = pathlib.Path(args.previous_job_dir).resolve()
    old = json.loads((previous/'manifest.json').read_text())
    if old.get('state')!='complete' or (job/'manifest.json').exists():
        raise ValueError('A completed previous job and a new job directory are required')
    assert_source_unchanged(old)
    job.mkdir(parents=True,mode=0o700,exist_ok=True)
    job.chmod(0o700)
    manifest = {key:old[key] for key in ('source','start_epoch','end_epoch','fixed_epoch','title',
                                       'backend_image','source_digests','target_site_id','target')}
    manifest.update(job_id=uuid.uuid4().hex,import_id=str(uuid.uuid4()),method_version=2,
                    affected_epoch=utc_epoch(args.affected_from),state='preparing',tables={},
                    method_labels=LABELS,previous_job_id=old['job_id'],previous_target_digests={})
    if not manifest['start_epoch']<manifest['affected_epoch']<manifest['fixed_epoch']<manifest['end_epoch']:
        raise ValueError('Invalid reconstruction boundaries')
    manifest['target_row_hash'] = target_guard(manifest)
    (job/'identity.key').write_bytes(os.urandom(32))
    (job/'identity.key').chmod(0o600)
    save(job,manifest)
    for table in TABLES:
        for suffix in ('.source.native.gz','.source.jsonl.gz'):
            os.link(previous/(table+suffix),job/(table+suffix))
        expected = {key:old['staging'][table][key] for key in ('rows','checksum')}
        current = digest_table(table,manifest['target_site_id'],exclude_site=True)
        if current!=expected:
            raise ValueError('Previous copy changed: '+table)
        manifest['previous_target_digests'][table] = current
        export_file('SELECT * FROM analytics.'+ident(table)+' WHERE site_id='+str(manifest['target_site_id'])+' FORMAT Native',job/(table+'.previous.native.gz'))
        export_file('SELECT * FROM analytics.'+ident(table)+' WHERE site_id='+str(manifest['target_site_id'])+' ORDER BY timestamp FORMAT JSONEachRow',job/(table+'.previous.jsonl.gz'))
        save(job,manifest)
    end = int(ch('SELECT toUnixTimestamp(now())-60 FORMAT TSV').strip())
    manifest['control_end_epoch'] = end
    export_file('SELECT * FROM analytics.events WHERE site_id='+str(manifest['source']['site_id'])+
                ' AND timestamp>=toDateTime('+str(manifest['fixed_epoch'])+') AND timestamp<toDateTime('+str(end)+') ORDER BY timestamp FORMAT JSONEachRow',job/'control.jsonl.gz')
    manifest['control_digest'] = digest_table('events',manifest['source']['site_id'],manifest['fixed_epoch'],end)
    manifest['state'] = 'prepared'
    save(job,manifest)
    print(json.dumps({'phase':'refinement_prepared','control_rows':manifest['control_digest']['rows']}),flush=True)


def anchor(event, log):
    result = {field:event.get(field,'') for field in PROFILE_FIELDS}
    result.update(hostname=event.get('hostname',''),legacy_id=log['old_id'],
                  canonical_id=log.get('canonical_id',log['native_id']),time_ms=event_ms(event))
    return result


def validate(job, manifest):
    logs = list(rows(job/'enriched-logs.jsonl.gz'))
    matcher = LogMatcher(logs)
    controls = list(rows(job/'control.jsonl.gz'))
    last = max(row['end_ms'] for row in logs)-5000
    first = manifest['fixed_epoch']*1000+5000
    covered = [event for event in controls if first<=event_ms(event)<last]
    if len(covered)<200:
        raise ValueError('Insufficient corrected-period events for an independent holdout')
    split = first+(last-first)//4
    training = [event for event in covered if event_ms(event)<split]
    calibration = matcher.calibrate(training)
    known = []
    counts = collections.Counter()
    for event in covered:
        candidates = matcher.candidates(event,broad=True)
        identities = {row.get('canonical_id',row['native_id']) for row in candidates}
        if len(identities)!=1:
            counts['ambiguous_or_unmatched'] += 1
            continue
        selected = min(candidates,key=lambda row:abs(row['start_ms']-event_ms(event)+matcher.offset_ms))
        phase = 'training' if event_ms(event)<split else 'holdout'
        counts[phase+'_cases'] += 1
        if event['user_id']!=next(iter(identities)):
            counts[phase+'_errors'] += 1
        else:
            known.append((event,selected))
    if counts['holdout_cases']<200 or counts['holdout_errors'] or counts['training_errors']:
        raise ValueError('Independent IP holdout failed: '+json.dumps(dict(counts)))
    anchors = [anchor(event,log) for event,log in known if (event_ms(event)//30000)%5!=0]
    bridge = ConservativeBridge(anchors)
    fallback = collections.Counter()
    middle = first+(last-first)//2
    for event,log in known:
        if (event_ms(event)//30000)%5!=0:
            continue
        partition = 'earlier' if event_ms(event)<middle else 'later'
        fallback['hidden_events'] += 1
        identity = bridge.match(event,log['old_id'])
        if identity is None:
            fallback['rejected_as_uncertain'] += 1
            continue
        fallback['accepted'] += 1
        fallback[partition+'_accepted'] += 1
        if identity!=event['user_id']:
            fallback['errors'] += 1
    enabled = fallback['accepted']>=400 and fallback['later_accepted']>=200 and not fallback['errors']
    report = {'ip_alignment':calibration,'ip_holdout':dict(counts),
              'control_start_epoch':manifest['fixed_epoch'],'control_end_epoch':manifest['control_end_epoch'],
              'log_covered_seconds':round((last-first)/1000),'control_events':len(controls),
              'control_users':len({event['user_id'] for event in controls}),
              'control_sessions':len({event['session_id'] for event in controls}),
              'control_profiles':len({tuple(event.get(field,'') for field in PROFILE_FIELDS) for event in controls}),
              'fallback_validation':dict(fallback),'fallback_enabled':enabled,
              'fallback_min_accepted':400,'fallback_min_later_accepted':200,
              'fallback_max_errors':0,'fallback_max_anchor_distance_seconds':60,
              'fallback_guard_seconds':120}
    manifest['validation'] = report
    manifest['state'] = 'validated'
    save(job,manifest)
    print(json.dumps({'phase':'validated',**report}),flush=True)
    return matcher


def affected(event, manifest):
    return manifest['affected_epoch']*1000<=event_ms(event)<manifest['fixed_epoch']*1000


def build(job, manifest):
    if manifest['state'] not in ('enriched','validated'):
        raise ValueError('Enrichment must complete before refinement')
    matcher = validate(job,manifest)
    assignments = {}
    anchors = []
    blocked = set()
    audit = collections.Counter()
    for index,event in enumerate(rows(job/'events.source.jsonl.gz')):
        if not affected(event,manifest):
            continue
        log,status = matcher.match(event)
        if log:
            assignments[index] = {'identity':log.get('canonical_id',log['native_id']),
                                  'geo':log['geo'],'method':'ip_correlated'}
            anchors.append(anchor(event,log))
        elif status=='ambiguous':
            blocked.add(index)
            audit['ambiguous_direct_matches'] += 1
    bridge = ConservativeBridge(anchors)
    for index,event in enumerate(rows(job/'events.source.jsonl.gz')):
        if not affected(event,manifest) or index in assignments or index in blocked:
            continue
        identity = bridge.match(event,event['user_id'])
        if identity is None:
            continue
        audit['fallback_candidates'] += 1
        if manifest['validation']['fallback_enabled']:
            assignments[index] = {'identity':identity,'method':'validated_bridge'}
        else:
            audit['fallback_withheld_insufficient_validation'] += 1
    sessionizer = Sessionizer((job/'identity.key').read_bytes())
    session_aliases = {}
    for index,event in enumerate(rows(job/'events.source.jsonl.gz')):
        if index in assignments:
            item = assignments[index]
            item['session'] = sessionizer.session(item['identity'],event_ms(event))
        elif event_ms(event)>=manifest['fixed_epoch']*1000:
            group = sessionizer.session(event['user_id'],event_ms(event))
            session_aliases.setdefault(group,event['session_id'])
    import gzip
    for table in TABLES:
        counters = collections.Counter()
        with gzip.open(job/(table+'.estimated.jsonl.gz'),'wt',encoding='utf-8',compresslevel=3) as output:
            for index,event in enumerate(rows(job/(table+'.source.jsonl.gz'))):
                event['site_id'] = 0
                if table=='events':
                    item = assignments.get(index)
                    if item:
                        method = item['method']
                        event['user_id'] = item['identity']
                        event['session_id'] = session_aliases.get(item['session'],item['session'])
                        for field,value in item.get('geo',{}).items():
                            if field in event:
                                event[field] = value
                    elif event_ms(event)<manifest['affected_epoch']*1000:
                        method = 'before_update'
                    elif event_ms(event)>=manifest['fixed_epoch']*1000:
                        method = 'after_fix'
                    else:
                        method = 'unresolved'
                    event['import_id'] = manifest['import_id']
                    event['tag'] = LABELS[method]
                    counters[method] += 1
                counters['rows'] += 1
                output.write(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n')
        if counters['rows']!=manifest['source_digests'][table]['rows']:
            raise ValueError('Refinement changed the number of events')
        manifest['tables'][table] = dict(counters)
        print(json.dumps({'phase':'refined','table':table,**dict(counters)}),flush=True)
    manifest['refinement_audit'] = dict(audit)
    manifest['state'] = 'built'
    save(job,manifest)


def preserved_digest(table,site_id,columns,condition):
    return queries('SELECT count() AS rows,toString(sum(cityHash64(toJSONString(tuple('+','.join(map(ident,columns))+'))))) AS checksum FROM analytics.'+ident(table)+' WHERE site_id='+str(site_id)+' AND '+condition)[0]


def check_preserved(table,site_id,manifest,target_table=None):
    columns = [column for column in table_columns(table) if column not in ('site_id','tag','import_id')]
    start = manifest['start_epoch']
    end = manifest['end_epoch']
    if table=='events':
        condition = '(timestamp<toDateTime('+str(manifest['affected_epoch'])+') OR timestamp>=toDateTime('+str(manifest['fixed_epoch'])+'))'
    else:
        condition = '1'
    condition += ' AND timestamp>=toDateTime('+str(start)+') AND timestamp<toDateTime('+str(end)+')'
    expected = preserved_digest(table,manifest['source']['site_id'],columns,condition)
    actual = preserved_digest(target_table or table,site_id,columns,condition)
    if expected!=actual:
        raise ValueError('Preserved records differ: '+table)
    return actual


def apply(job, manifest):
    if manifest['state'] not in ('built','replacing_copy'):
        raise ValueError('Refinement must be built before replacing the copy')
    assert_source_unchanged(manifest)
    target_guard(manifest)
    stage(job,manifest)
    for table in TABLES:
        check_preserved(table,0,manifest,manifest['staging'][table]['table'])
    target_guard(manifest)
    assert_source_unchanged(manifest)
    manifest['state'] = 'replacing_copy'
    save(job,manifest)
    target = int(manifest['target_site_id'])
    for table in TABLES:
        expected = {key:manifest['staging'][table][key] for key in ('rows','checksum')}
        current = digest_table(table,target,exclude_site=True)
        if current==expected:
            continue
        resuming_empty = not current['rows'] and manifest.get('replacement_started',{}).get(table)
        if current!=manifest['previous_target_digests'][table] and not resuming_empty:
            raise ValueError('Copy changed since backup; refusing replacement: '+table)
        if target==int(manifest['source']['site_id']):
            raise ValueError('Refusing to replace the source site')
        if not resuming_empty:
            manifest.setdefault('replacement_started',{})[table] = True
            save(job,manifest)
            ch('ALTER TABLE analytics.'+ident(table)+' DELETE WHERE site_id='+str(target)+' SETTINGS mutations_sync=2',readonly=False)
        columns = table_columns(table)
        selection = ['toUInt16('+str(target)+')' if column=='site_id' else ident(column) for column in columns]
        ch('INSERT INTO analytics.'+ident(table)+' ('+','.join(map(ident,columns))+') SELECT '+','.join(selection)+
           ' FROM analytics.'+ident(manifest['staging'][table]['table'])+' WHERE site_id=0',readonly=False)
        if digest_table(table,target,exclude_site=True)!=expected:
            raise ValueError('Refined copy checksum mismatch: '+table)
        print(json.dumps({'phase':'copy_updated','table':table,'rows':expected['rows']}),flush=True)
    assert_source_unchanged(manifest)
    manifest['preserved_digests'] = {table:check_preserved(table,target,manifest) for table in TABLES}
    manifest['source_unchanged'] = True
    manifest['state'] = 'complete'
    save(job,manifest)
    print(json.dumps({'phase':'complete','target_site_id':target,'source_unchanged':True}),flush=True)


def report(job,manifest):
    if manifest['state']!='complete':
        raise ValueError('The updated copy is not complete')
    assert_source_unchanged(manifest)
    for table in TABLES:
        check_preserved(table,manifest['target_site_id'],manifest)
    result = {key:manifest[key] for key in ('target_site_id','title','start_epoch','end_epoch','affected_epoch',
                                          'fixed_epoch','validation','tables','refinement_audit','source_unchanged')}
    result['daily'] = queries("SELECT site_id,toString(toDate(timestamp,'Europe/Moscow')) AS date,count() AS events,countIf(type='pageview') AS pageviews,uniqExact(user_id) AS users,uniqExact(session_id) AS sessions FROM analytics.events WHERE site_id IN ("+str(manifest['source']['site_id'])+','+str(manifest['target_site_id'])+') AND timestamp>=toDateTime('+str(manifest['start_epoch'])+') AND timestamp<toDateTime('+str(manifest['end_epoch'])+') GROUP BY site_id,date ORDER BY date,site_id')
    previous = collections.defaultdict(lambda:{'users':set(),'sessions':set(),'events':0})
    for event in rows(job/'events.previous.jsonl.gz'):
        day = datetime.datetime.fromtimestamp(event_ms(event)/1000,datetime.timezone(datetime.timedelta(hours=3))).date().isoformat()
        previous[day]['users'].add(event['user_id'])
        previous[day]['sessions'].add(event['session_id'])
        previous[day]['events'] += 1
    result['previous_daily'] = [{'date':day,'users':len(values['users']),'sessions':len(values['sessions']),'events':values['events']} for day,values in sorted(previous.items())]
    result['methods'] = queries('SELECT tag,count() AS events,uniqExact(user_id) AS users,uniqExact(session_id) AS sessions FROM analytics.events WHERE site_id='+str(manifest['target_site_id'])+' GROUP BY tag ORDER BY tag')
    result['backup_available'] = all((job/(table+'.previous.native.gz')).exists() for table in TABLES)
    result['healthy_records_match_source'] = True
    path = job/'result.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    path.chmod(0o600)
    print(json.dumps(result,ensure_ascii=False,indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('prepare','build','apply','report'))
    parser.add_argument('--job-dir',required=True)
    parser.add_argument('--previous-job-dir')
    parser.add_argument('--affected-from')
    args = parser.parse_args()
    os.umask(0o077)
    job = pathlib.Path(args.job_dir).resolve()
    if args.action=='prepare':
        prepare(args,job)
        return
    manifest = json.loads((job/'manifest.json').read_text())
    if args.action=='build':
        build(job,manifest)
    elif args.action=='apply':
        apply(job,manifest)
    else:
        report(job,manifest)


if __name__=='__main__':
    main()
