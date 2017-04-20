from __future__ import absolute_import

from sentry.runner import configure
configure()

import functools
import logging
from collections import defaultdict
from datetime import timedelta

from sentry.constants import DEFAULT_LOGGER_NAME, LOG_LEVELS_MAP
from sentry.event_manager import ScoreClause, generate_culprit, get_hashes_for_event, md5_from_hash
from sentry.models import Event, EventMapping, EventTag, Group, GroupHash, GroupRelease, GroupTagKey, GroupTagValue, Release, UserReport
from sentry.tsdb import backend as tsdb


def get_events(hashes):
    events = Event.objects.order_by('id').filter(group_id__in=set(hash.group_id for hash in hashes))
    Event.objects.bind_nodes(events, 'data')
    return filter(
        lambda event: md5_from_hash(get_hashes_for_event(event)[0]) in set(hash.hash for hash in hashes),
        events,
    )


def get_group_attributes(events):
    return reduce(
        lambda attributes, event: {
            'project': attributes.get('project', event.project),
            'short_id': attributes.get('short_id') or event.project.next_short_id(),
            'platform': attributes.get('platform', event.platform),
            'message': event.message if event.message else attributes.get('message'),
            'score': ScoreClause.calculate(
                attributes.get('times_seen', 0) + 1,
                max(
                    attributes.get('last_seen'),
                    event.datetime,
                ) if attributes.get('last_seen') is not None else event.datetime,
            ),
            'culprit': generate_culprit(event.data, event.platform),
            'logger': attributes.get('logger', event.get_tag('logger') or DEFAULT_LOGGER_NAME),
            'level': LOG_LEVELS_MAP.get(
                event.get_tag('level'),
                logging.ERROR,
            ),
            'first_seen': attributes.get('first_seen', event.datetime),
            'last_seen': max(
                attributes.get('last_seen'),
                event.datetime,
            ) if attributes.get('last_seen') is not None else event.datetime,
            'active_at': attributes.get('active_at', event.datetime),
            'data': {
                'last_received': event.data.get('received') or float(event.datetime.strftime('%s')),
                'type': event.data['type'],
                'metadata': event.data['metadata'],
            },
            'times_seen': attributes.get('times_seen', 0) + 1,
            'first_release': Release.objects.get(
                organization_id=event.project.organization_id,
                version=event.get_tag('sentry:release')
            ) if event.get_tag('sentry:release') else None,
        },
        events,
        {},
    )


def get_group_releases(events):
    def process_event(releases, event):
        release = event.get_tag('sentry:release')

        # XXX: literally no idea what the canonical source is for this btwn the
        # tag and data attr
        environment = event.data.get('environment', '')  # XXX: not nullable lmao

        key = (environment, release)
        if not release:
            return releases

        if key in releases:
            last_seen = releases[key]['last_seen']
            releases[key]['last_seen'] = event.datetime if last_seen < event.datetime - timedelta(seconds=60) else last_seen
        else:
            releases[key] = {
                'environment': environment,
                'first_seen': event.datetime,
                'last_seen': event.datetime,
                'release_id': Release.objects.get(
                    organization_id=event.project.organization_id,
                    version=release,
                ).id,
            }

        return releases

    return reduce(
        process_event,
        events,
        {},
    ).values()


def get_tag_data(events):
    def update_tags(tags, event):
        for key, value in event.get_tags():
            values = tags.setdefault(key, {})
            if value not in values:
                values[value] = (1, event.datetime, event.datetime)
            else:
                count, first_seen, last_seen = values[value]
                values[value] = (
                    count + 1,
                    first_seen,
                    event.datetime,
                )
        return tags

    return reduce(
        update_tags,
        events,
        {},
    )


def get_tsdb_data(events):
    def collector((counters, sets, frequencies), event):
        counters[tsdb.models.group][event.datetime] += 1
        # sets[tsdb.models.users_affected_by_group][event.datetime].add(event_user.tag_value)
        # frequencies: tsdb.models.frequent_environments_by_group
        # frequencies: tsdb.models.frequent_releases_by_group
        return counters, sets, frequencies
    return reduce(
        collector,
        events,
        (
            defaultdict(functools.partial(defaultdict, int)),
            defaultdict(functools.partial(defaultdict, set)),
            defaultdict(functools.partial(defaultdict, dict)),
        ),
    )


def unmerge(hashes):
    # TODO: lol transactions
    # TODO: make it iterative
    events = get_events(hashes)

    group = Group.objects.create(**get_group_attributes(events))
    GroupHash.objects.filter(id__in=[hash.id for hash in hashes]).update(group=group)

    # - decrement old times seen
    # - fix old group attributes

    event_id_set = set(event.id for event in events)

    Event.objects.filter(id__in=event_id_set).update(group_id=group.id)
    EventTag.objects.filter(event_id__in=event_id_set).update(group_id=group.id)

    event_id_set = set(event.event_id for event in events)

    EventMapping.objects.filter(
        project_id=group.project_id,
        event_id__in=event_id_set,
    ).update(group_id=group.id)

    UserReport.objects.filter(
        project=group.project,
        event_id__in=event_id_set,
    ).update(group=group)

    for attributes in get_group_releases(events):
        # TODO: technically this should also adjust the timestamps for
        # ReleaseEnvironment too
        GroupRelease.objects.create(
            project_id=group.project_id,
            group_id=group.id,
            **attributes
        )

    for key, values in get_tag_data(events).items():
        GroupTagKey.objects.create(
            project=group.project,
            group=group,
            key=key,
            values_seen=len(values),
        )

        for value, (count, first_seen, last_seen) in values.items():
            GroupTagValue.objects.create(
                project=group.project,
                group=group,
                times_seen=count,
                key=key,
                value=value,
                last_seen=first_seen,
                first_seen=last_seen,
            )

            # TODO: decrement, possibly delete old tag records, also fix
            # first/last seen on these bad boys

    # TODO: tsdb: this needs to support multiple timestamp incrs
    counters, sets, frequencies = get_tsdb_data(events)

    # - increment new group
    # - decrement old group
    # - increment new frequency tables
    # - increment new distinct counter

    # TODO: activity thing for both groups
