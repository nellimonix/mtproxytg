import bisect
import collections
import datetime
import hashlib
import hmac
import json
import math
import statistics

AGENT_FIELDS = ('browser', 'browser_version', 'operating_system', 'operating_system_version')
PROFILE_FIELDS = AGENT_FIELDS + ('screen_width', 'screen_height', 'language')


def event_ms(event):
    value = event.get('timestamp_ms') or event['timestamp']
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return round(parsed.timestamp() * 1000)


def identity_digest(key, value):
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:24]


def technical_identity(key, event):
    values = [event.get(field, '') for field in PROFILE_FIELDS]
    return identity_digest(key, 'profile\0' + json.dumps(values, ensure_ascii=False, separators=(',', ':')))


def agent_key(event):
    return (event.get('hostname', ''),) + tuple(event.get(field, '') for field in AGENT_FIELDS)


class LogMatcher:
    def __init__(self, logs):
        self.index = collections.defaultdict(list)
        self.broad = collections.defaultdict(list)
        self.offset_ms = 0
        self.tolerance_ms = 250
        for log in logs:
            key = agent_key(log)
            self.index[(key, log['old_id'])].append(log)
            self.broad[key].append(log)
        for mapping in (self.index, self.broad):
            for key, records in mapping.items():
                records.sort(key=lambda row:row['start_ms'])
                mapping[key] = ([row['start_ms'] for row in records], records)

    def candidates(self, event, broad=False, offset_ms=None, tolerance_ms=None):
        key = agent_key(event)
        bucket = self.broad.get(key) if broad else self.index.get((key, event['user_id']))
        if not bucket:
            return []
        times, records = bucket
        offset = self.offset_ms if offset_ms is None else offset_ms
        tolerance = self.tolerance_ms if tolerance_ms is None else tolerance_ms
        timestamp = event_ms(event) - offset
        precision = 0 if event.get('timestamp_ms') else 999
        start = bisect.bisect_left(times, timestamp - tolerance)
        end = bisect.bisect_right(times, timestamp + precision + tolerance)
        return records[start:end]

    def calibrate(self, events):
        differences = []
        events = list(events)
        for event in events:
            candidates = [row for row in self.candidates(event, broad=True, offset_ms=0, tolerance_ms=3000)
                          if row.get('canonical_id',row['native_id']) == event['user_id']]
            if candidates:
                nearest = min(candidates, key=lambda row:abs(event_ms(event)-row['start_ms']))
                differences.append(event_ms(event)-nearest['start_ms'])
        if len(differences) < 20:
            raise ValueError('Insufficient post-fix samples for IP correlation')
        self.offset_ms = statistics.median(differences)
        deviations = sorted(abs(value-self.offset_ms) for value in differences)
        p95 = deviations[min(len(deviations)-1, math.ceil(len(deviations)*0.95)-1)]
        if p95 > 1500:
            raise ValueError('Proxy and application timestamps cannot be aligned reliably')
        self.tolerance_ms = max(100, min(750, math.ceil(p95)+50))
        checked = 0
        correct = 0
        ambiguous = 0
        for event in events:
            candidates = self.candidates(event, broad=True)
            identities = {row.get('canonical_id',row['native_id']) for row in candidates}
            if len(identities) == 1:
                checked += 1
                correct += event['user_id'] in identities
            elif len(identities) > 1:
                ambiguous += 1
        precision = correct/checked if checked else 0
        report = {'alignment_samples':len(differences), 'clock_offset_ms':self.offset_ms,
                'tolerance_ms':self.tolerance_ms, 'validation_cases':checked,
                'validation_correct':correct, 'validation_precision':precision,
                'validation_ambiguous':ambiguous,
                'known_identity_aliases':sum(bool(row.get('canonical_id') and row['canonical_id']!=row['native_id'])
                                            for records in self.broad.values() for row in records[1])}
        if checked < 20 or precision < 0.98:
            raise ValueError('IP correlation did not pass post-fix validation: '+json.dumps(report))
        return report

    def match(self, event):
        candidates = self.candidates(event)
        identities = {row['target_identity'] for row in candidates}
        if len(identities) == 1:
            timestamp = event_ms(event)-self.offset_ms
            return min(candidates, key=lambda row:abs(row['start_ms']-timestamp)), 'ip_correlated'
        return None, 'ambiguous' if len(identities)>1 else 'unmatched'


class Sessionizer:
    def __init__(self, key):
        self.key = key
        self.last = {}

    def session(self, identity, timestamp):
        previous = self.last.get(identity)
        if previous is None or timestamp-previous[0] >= 30*60*1000:
            session_id = identity_digest(self.key, 'session\0'+identity+'\0'+str(timestamp))
        else:
            session_id = previous[1]
        self.last[identity] = (max(timestamp, previous[0]) if previous else timestamp, session_id)
        return session_id
