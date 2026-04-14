use crate::gossipsub::topic::{
    AGGREGATION_TOPIC, ATTESTATION_SUBNET_PREFIX, BLOCK_TOPIC, GossipsubKind, GossipsubTopic,
    SSZ_SNAPPY_ENCODING_POSTFIX, TOPIC_PREFIX, compute_subnet_id, get_subscription_topics,
};

const TEST_SUBNET_COUNT: u64 = 1;
use libp2p::gossipsub::TopicHash;

#[test]
fn test_topic_decode_valid_block() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(decoded.fork, "genesis");
    assert_eq!(decoded.kind, GossipsubKind::Block);
}

#[test]
fn test_topic_decode_invalid_prefix() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        "wrongprefix", "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_decode_invalid_encoding() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, "wrong_encoding"
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_decode_invalid_kind() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", "invalid_kind", SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_decode_invalid_part_count() {
    let topic_hash = TopicHash::from_raw("/only/two/parts");

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_to_string() {
    let topic = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };

    let topic_str = topic.to_string();
    assert_eq!(
        topic_str,
        format!(
            "/{}/{}/{}/{}",
            TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
        )
    );
}

#[test]
fn test_topic_encoding_decoding_roundtrip() {
    let original = GossipsubTopic {
        fork: "testfork".to_string(),
        kind: GossipsubKind::AttestationSubnet(0),
    };

    let topic_hash: TopicHash = original.clone().into();
    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(original.fork, decoded.fork);
    assert_eq!(original.kind, decoded.kind);
}

#[test]
fn test_gossipsub_kind_display() {
    assert_eq!(GossipsubKind::Block.to_string(), BLOCK_TOPIC);
    assert_eq!(GossipsubKind::Aggregation.to_string(), AGGREGATION_TOPIC);
    assert_eq!(
        GossipsubKind::AttestationSubnet(0).to_string(),
        format!("{ATTESTATION_SUBNET_PREFIX}0")
    );
    assert_eq!(
        GossipsubKind::AttestationSubnet(5).to_string(),
        format!("{ATTESTATION_SUBNET_PREFIX}5")
    );
}

#[test]
fn test_topic_decode_valid_aggregation() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", AGGREGATION_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(decoded.fork, "genesis");
    assert_eq!(decoded.kind, GossipsubKind::Aggregation);
}

#[test]
fn test_topic_decode_valid_attestation_subnet() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", "attestation_0", SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(decoded.fork, "genesis");
    assert_eq!(decoded.kind, GossipsubKind::AttestationSubnet(0));
}

#[test]
fn test_topic_decode_valid_attestation_subnet_large_id() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", "attestation_42", SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(decoded.fork, "genesis");
    assert_eq!(decoded.kind, GossipsubKind::AttestationSubnet(42));
}

#[test]
fn test_topic_decode_invalid_attestation_subnet_id() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", "attestation_abc", SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_aggregation_roundtrip() {
    let original = GossipsubTopic {
        fork: "testfork".to_string(),
        kind: GossipsubKind::Aggregation,
    };

    let topic_hash: TopicHash = original.clone().into();
    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(original.fork, decoded.fork);
    assert_eq!(original.kind, decoded.kind);
}

#[test]
fn test_topic_attestation_subnet_roundtrip() {
    let original = GossipsubTopic {
        fork: "testfork".to_string(),
        kind: GossipsubKind::AttestationSubnet(7),
    };

    let topic_hash: TopicHash = original.clone().into();
    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(original.fork, decoded.fork);
    assert_eq!(original.kind, decoded.kind);
}

#[test]
fn test_topic_equality() {
    let topic1 = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };
    let topic2 = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };
    let topic3 = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Aggregation,
    };
    let topic4 = GossipsubTopic {
        fork: "genesis2".to_string(),
        kind: GossipsubKind::Aggregation,
    };

    assert_eq!(topic1, topic2);
    assert_ne!(topic1, topic3);
    assert_ne!(topic3, topic4); // Same kind, different fork
}

#[test]
fn test_topic_hash_conversion() {
    let topic = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };

    let hash: TopicHash = topic.into();
    let expected = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );

    assert_eq!(hash.as_str(), expected);
}

#[test]
fn test_get_subscription_topics_aggregator_with_validator() {
    // Aggregator with a registered validator subscribes to the validator-derived subnet.
    let topics =
        get_subscription_topics("myfork".to_string(), &[0u64], true, &[], TEST_SUBNET_COUNT);

    // Block + Aggregation + derived attestation subnet(s)
    let kinds: Vec<_> = topics.iter().map(|t| t.kind.clone()).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Aggregation));
    assert!(
        kinds.contains(&GossipsubKind::AttestationSubnet(compute_subnet_id(
            0,
            TEST_SUBNET_COUNT
        )))
    );

    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}

#[test]
fn test_get_subscription_topics_aggregator_no_validator_fallback() {
    // Aggregator with no registered validators falls back to subnet 0.
    let topics = get_subscription_topics("myfork".to_string(), &[], true, &[], TEST_SUBNET_COUNT);

    let kinds: Vec<_> = topics.iter().map(|t| t.kind.clone()).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Aggregation));
    assert!(kinds.contains(&GossipsubKind::AttestationSubnet(0)));

    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}

#[test]
fn test_get_subscription_topics_aggregator_explicit_subnets() {
    // Aggregator with explicit aggregate_subnet_ids subscribes to both validator-derived
    // and the explicit subnets.
    let topics = get_subscription_topics(
        "myfork".to_string(),
        &[0u64],
        true,
        &[1u64, 2u64],
        TEST_SUBNET_COUNT,
    );

    let kinds: Vec<_> = topics.iter().map(|t| t.kind.clone()).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Aggregation));
    assert!(
        kinds.contains(&GossipsubKind::AttestationSubnet(compute_subnet_id(
            0,
            TEST_SUBNET_COUNT
        )))
    );
    assert!(kinds.contains(&GossipsubKind::AttestationSubnet(1)));
    assert!(kinds.contains(&GossipsubKind::AttestationSubnet(2)));

    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}

#[test]
fn test_get_subscription_topics_non_aggregator_validator() {
    // Non-aggregator validator subscribes only to their own derived subnet.
    let validator_id = 5u64;
    let topics = get_subscription_topics(
        "myfork".to_string(),
        &[validator_id],
        false,
        &[],
        TEST_SUBNET_COUNT,
    );

    // Block + Aggregation + only one attestation subnet
    assert_eq!(topics.len(), 3);

    let kinds: Vec<_> = topics.iter().map(|t| t.kind.clone()).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Aggregation));
    assert!(
        kinds.contains(&GossipsubKind::AttestationSubnet(compute_subnet_id(
            validator_id,
            TEST_SUBNET_COUNT
        )))
    );

    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}

#[test]
fn test_get_subscription_topics_non_aggregator_multi_validator() {
    // Non-aggregator with multiple validators subscribes to each derived subnet (deduped).
    let topics = get_subscription_topics(
        "myfork".to_string(),
        &[0u64, 1u64, 2u64],
        false,
        &[],
        TEST_SUBNET_COUNT,
    );

    let kinds: Vec<_> = topics.iter().map(|t| t.kind.clone()).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Aggregation));
    // All three validators map to the same subnet (N % 1 = 0) with subnet_count=1
    assert!(kinds.contains(&GossipsubKind::AttestationSubnet(0)));

    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}

#[test]
fn test_get_subscription_topics_non_validator_skips_attestation() {
    // Non-validator, non-aggregator node subscribes to NO attestation topics (saves bandwidth).
    // This aligns with leanSpec PR #482: subnet filtering at the p2p subscription layer.
    let topics = get_subscription_topics("myfork".to_string(), &[], false, &[], TEST_SUBNET_COUNT);

    // Block + Aggregation only — no attestation subnets
    assert_eq!(topics.len(), 2);

    let kinds: Vec<_> = topics.iter().map(|t| t.kind.clone()).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Aggregation));

    // Confirm no attestation topic is present
    for kind in &kinds {
        assert!(!matches!(kind, GossipsubKind::AttestationSubnet(_)));
    }

    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}
