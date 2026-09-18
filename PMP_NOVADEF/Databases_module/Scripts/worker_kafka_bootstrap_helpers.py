#!/usr/bin/env python3
"""
Kafka bootstrap helpers for newly discovered topics in the Kafka -> Redis worker.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

from confluent_kafka import Consumer, KafkaError, KafkaException, OFFSET_INVALID, TopicPartition
from confluent_kafka.admin import AdminClient, OffsetSpec
from confluent_kafka import ConsumerGroupTopicPartitions


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BootstrapRecord:
    topic: str
    partition: int
    value: bytes


def get_topic_partitions(admin_client: AdminClient, topic: str) -> list[TopicPartition]:
    metadata = admin_client.list_topics(topic=topic, timeout=10)
    topic_metadata = metadata.topics.get(topic)
    if topic_metadata is None or topic_metadata.error is not None:
        return []
    return [TopicPartition(topic, partition_id) for partition_id in sorted(topic_metadata.partitions.keys())]


def get_group_offsets(
    admin_client: AdminClient,
    group_id: str,
    topic_partitions: list[TopicPartition],
) -> dict[int, int]:
    if not topic_partitions:
        return {}

    request = [ConsumerGroupTopicPartitions(group_id, topic_partitions)]
    futures = admin_client.list_consumer_group_offsets(request, request_timeout=10)
    result = futures[group_id].result()
    offsets: dict[int, int] = {}
    for topic_partition in result.topic_partitions or []:
        offsets[int(topic_partition.partition)] = int(topic_partition.offset)
    return offsets


def get_partition_watermarks(
    admin_client: AdminClient,
    topic_partitions: list[TopicPartition],
) -> dict[int, tuple[int, int]]:
    if not topic_partitions:
        return {}

    earliest_futures = admin_client.list_offsets(
        {tp: OffsetSpec.earliest() for tp in topic_partitions},
        request_timeout=10,
    )
    latest_futures = admin_client.list_offsets(
        {tp: OffsetSpec.latest() for tp in topic_partitions},
        request_timeout=10,
    )

    watermarks: dict[int, tuple[int, int]] = {}
    for topic_partition in topic_partitions:
        earliest = int(earliest_futures[topic_partition].result().offset)
        latest = int(latest_futures[topic_partition].result().offset)
        watermarks[int(topic_partition.partition)] = (earliest, latest)
    return watermarks


def consume_new_topic_bootstrap(
    admin_client: AdminClient,
    bootstrap_servers: str,
    topic: str,
    topic_partitions: list[TopicPartition],
    max_messages_per_partition: int,
) -> tuple[list[BootstrapRecord], list[TopicPartition]]:
    watermarks = get_partition_watermarks(admin_client, topic_partitions)
    partitions_to_assign: list[TopicPartition] = []
    consumed_counts: dict[int, int] = {}
    next_offsets: dict[int, int] = {}
    upper_bounds: dict[int, int] = {}

    for topic_partition in topic_partitions:
        partition = int(topic_partition.partition)
        earliest, latest = watermarks.get(partition, (OFFSET_INVALID, OFFSET_INVALID))
        if earliest == OFFSET_INVALID or latest == OFFSET_INVALID:
            continue
        partitions_to_assign.append(TopicPartition(topic, partition, earliest))
        consumed_counts[partition] = 0
        next_offsets[partition] = earliest
        upper_bounds[partition] = latest

    if not partitions_to_assign:
        return [], []

    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap_servers,
            "group.id": f"{topic}-bootstrap-reader",
            "enable.auto.commit": False,
            "allow.auto.create.topics": False,
            "enable.partition.eof": True,
            "socket.keepalive.enable": True,
            "auto.offset.reset": "earliest",
        }
    )

    records: list[BootstrapRecord] = []
    partitions_done = {
        tp.partition: upper_bounds[tp.partition] <= next_offsets[tp.partition]
        for tp in partitions_to_assign
    }

    try:
        consumer.assign(partitions_to_assign)
        idle_polls = 0

        while not all(partitions_done.values()):
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                idle_polls += 1
                if idle_polls >= 3:
                    break
                continue

            idle_polls = 0

            if msg.error():
                error = msg.error()
                if error.code() == KafkaError._PARTITION_EOF:
                    partitions_done[int(msg.partition())] = True
                    continue
                raise KafkaException(error)

            partition = int(msg.partition())
            current_offset = int(msg.offset())
            next_offsets[partition] = current_offset + 1
            records.append(
                BootstrapRecord(
                    topic=msg.topic(),
                    partition=partition,
                    value=msg.value(),
                )
            )
            consumed_counts[partition] += 1

            if (
                consumed_counts[partition] >= max_messages_per_partition
                or next_offsets[partition] >= upper_bounds[partition]
            ):
                partitions_done[partition] = True

    finally:
        consumer.close()

    committed_offsets = [
        TopicPartition(topic, partition, next_offsets[partition])
        for partition in sorted(next_offsets.keys())
    ]
    return records, committed_offsets


def commit_group_offsets(
    admin_client: AdminClient,
    group_id: str,
    topic_partitions: list[TopicPartition],
) -> None:
    if not topic_partitions:
        return
    request = [ConsumerGroupTopicPartitions(group_id, topic_partitions)]
    futures = admin_client.alter_consumer_group_offsets(request, request_timeout=10)
    futures[group_id].result()


def find_partitions_without_group_offsets(
    admin_client: AdminClient,
    group_id: str,
    topic: str,
) -> list[TopicPartition]:
    topic_partitions = get_topic_partitions(admin_client, topic)
    if not topic_partitions:
        return []

    offsets = get_group_offsets(admin_client, group_id, topic_partitions)
    return [
        TopicPartition(topic, topic_partition.partition)
        for topic_partition in topic_partitions
        if offsets.get(int(topic_partition.partition), OFFSET_INVALID) == OFFSET_INVALID
    ]
