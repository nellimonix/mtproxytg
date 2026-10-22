import argparse
import json
import os
import pathlib

from promote import fingerprint
from reconstruct import ch, digest_table, ident, pg, quote, run, source_site, table_columns
from refine import queries, target_guard

TABLES = ('events','bot_events','bot_observations','monitor_events','session_replay_events',
          'session_replay_metadata','session_replay_metadata_v2')


def remove(args):
    reference_job = pathlib.Path(args.reference_job_dir).resolve()
    reference = json.loads((reference_job/'manifest.json').read_text())
    target = int(reference['target_site_id'])
    source = int(reference['source']['site_id'])
    if reference['state']!='complete' or reference.get('method_version')!=2 or target==source:
        raise ValueError('A distinct completed reconstruction copy is required')
    job = pathlib.Path(args.job_dir).resolve()
    metadata_exists = bool(int(pg('SELECT count(*) FROM sites WHERE site_id='+str(target)+';')))
    if metadata_exists:
        target_guard(reference)
    else:
        previous_site = json.loads((job/'deleted-site.json').read_text())
        if (previous_site['site_id']!=target or previous_site['public']
                or previous_site['id']!=reference['target']['id']
                or previous_site['name']!=reference['title']
                or previous_site['organization_id']!=reference['source']['organization_id']
                or previous_site['created_by']!=reference['source']['created_by']):
            raise ValueError('Deleted site does not match the reconstruction copy')
    if run(['docker','inspect','backend','--format','{{.Image}}']).decode().strip()!=reference['backend_image']:
        raise ValueError('Installed backend image changed')
    for table in ('events','bot_events','bot_observations'):
        expected = {key:reference['staging'][table][key] for key in ('rows','checksum')}
        actual = digest_table(table,target,exclude_site=True)
        if actual!=expected and (metadata_exists or actual['rows']):
            raise ValueError('Copy data differs from the reconstruction snapshot')
    job.mkdir(parents=True,mode=0o700,exist_ok=True)
    job.chmod(0o700)
    cutoff = int(ch('SELECT toUnixTimestamp(now())-300 FORMAT TSV').strip())
    where = 'site_id='+str(source)+' AND timestamp>=toStartOfMonth(toDateTime('+str(reference['start_epoch'])+')) AND timestamp<toDateTime('+str(cutoff)+')'
    main_row_hash = source_site(source)['row_hash']
    before = {table:fingerprint(table,table_columns(table),where) for table in ('events','bot_events','bot_observations')}
    if metadata_exists:
        site_json = pg('SELECT row_to_json(s) FROM sites s WHERE site_id='+str(target)+';')
        (job/'deleted-site.json').write_text(site_json+'\n')
        (job/'deleted-site.json').chmod(0o600)
    existing = [row['table_name'] for row in queries("SELECT `table` AS table_name FROM system.columns WHERE database='analytics' AND `name`='site_id' AND `table` IN ("+','.join(quote(table) for table in TABLES)+')')]
    if not {'events','bot_events','bot_observations'}.issubset(existing):
        raise ValueError('Required analytics tables were not discovered')
    counts = {table:int(ch('SELECT count() FROM analytics.'+ident(table)+' WHERE site_id='+str(target)+' FORMAT TSV').strip()) for table in existing}
    print(json.dumps({'phase':'validated','copy_site_id':target,'copy_rows':counts,'main_site_id':source}),flush=True)
    code = """
import {siteConfigurationLifecycle} from '/app/dist/services/sites/siteConfigurationLifecycle.js';
const siteId=Number(process.argv[1]);
if (!Number.isInteger(siteId) || siteId<=0) throw new Error('Invalid site identifier');
await siteConfigurationLifecycle.delete(siteId);
process.stdout.write(JSON.stringify({removed_site:siteId})+'\\n');
process.exit(0);
"""
    if metadata_exists:
        run(['docker','exec','backend','node','--input-type=module','-e',code,str(target)],timeout=180)
    if int(pg('SELECT count(*) FROM sites WHERE site_id='+str(target)+';')):
        raise ValueError('Site metadata was not removed')
    for table in existing:
        if counts[table]:
            ch('ALTER TABLE analytics.'+ident(table)+' DELETE WHERE site_id='+str(target)+' SETTINGS mutations_sync=2',readonly=False)
        if int(ch('SELECT count() FROM analytics.'+ident(table)+' WHERE site_id='+str(target)+' FORMAT TSV').strip()):
            raise ValueError('Deleted copy still has rows: '+table)
    after = {table:fingerprint(table,table_columns(table),where) for table in before}
    if after!=before or source_site(source)['row_hash']!=main_row_hash:
        raise ValueError('Main statistics or settings changed')
    backup_root = pathlib.Path(args.promotion_job_dir).resolve()
    promotion = json.loads((backup_root/'manifest.json').read_text())
    if promotion['state']!='complete' or int(promotion['site_id'])!=source:
        raise ValueError('Production promotion backup is not complete')
    preserved = queries('SELECT count() AS events FROM analytics.events WHERE site_id='+str(source)+
                        ' AND import_id='+quote(promotion['import_id']))[0]['events']
    if preserved!=promotion['confirmed_rows']:
        raise ValueError('Promoted IP restorations changed')
    result = {'deleted_copy_site_id':target,'site_metadata_removed':True,'copy_data_remaining':0,
              'deleted_rows':counts,'main_site_id':source,'main_statistics_unchanged':True,
              'main_events_verified':before['events']['rows'],'main_settings_unchanged':True,
              'promoted_ip_events_preserved':preserved,'production_backups_preserved':all((backup_root/name).is_file() for name in promotion['backup_sha256'])}
    if not result['production_backups_preserved']:
        raise ValueError('Production backup files are missing')
    (job/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    (job/'result.json').chmod(0o600)
    print(json.dumps(result,ensure_ascii=False,indent=2),flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference-job-dir',required=True)
    parser.add_argument('--promotion-job-dir',required=True)
    parser.add_argument('--job-dir',required=True)
    args = parser.parse_args()
    os.umask(0o077)
    remove(args)


if __name__=='__main__':
    main()
