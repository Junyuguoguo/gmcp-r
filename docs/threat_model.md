# GMCP-R Protocol: Threat Model Document

## 1. Overview

This document defines the threat model for the GMCP-R (Memory-Continuity-Aware Secure Recovery Protocol) protocol. The threat model specifies the adversary's capabilities, the assets to be protected, and the security objectives.

---

## 2. System Model

### 2.1 Protocol Participants

- **Client**: Initiates communication, sends messages with memory chain
- **Server**: Receives and verifies messages, issues MemoryTickets
- **Adversary**: Attempts to compromise communication security

### 2.2 Communication Channel

- **Transport**: TCP/IP
- **Topology**: Client-Server (1:1)
- **Properties**: Asynchronous, potentially unreliable

---

## 3. Adversary Model

### 3.1 Adversary Capabilities

We consider a **Dolev-Yao** adversary with the following capabilities:

#### Network-Level Capabilities
1. **Intercept**: Read all messages between client and server
2. **Modify**: Alter message content in transit
3. **Delete**: Drop messages (prevent delivery)
4. **Inject**: Insert new messages into the channel
5. **Replay**: Re-send previously captured messages
6. **Reorder**: Change message delivery order

#### Limitations
1. **No Cryptanalysis**: Cannot break HMAC-SHA256 or SHA-256
2. **No Key Compromise**: Cannot obtain the shared secret key
3. **No Endpoint Control**: Cannot compromise client or server
4. **No Side Channels**: Cannot exploit timing or power analysis

### 3.2 Adversary Goals

The adversary aims to:

1. **Forge Messages**: Create messages that appear legitimate
2. **Modify Undetected**: Change message content without detection
3. **Replay Attacks**: Re-use old messages successfully
4. **Break Continuity**: Disrupt memory chain verification
5. **Compromise Recovery**: Forge or replay MemoryTickets

---

## 4. Assets to Protect

### 4.1 Primary Assets

1. **Message Integrity**: Payload content cannot be modified
2. **Message Authentication**: Messages must originate from legitimate sender
3. **Message Freshness**: Old messages cannot be replayed
4. **Memory Continuity**: Communication history is verifiable
5. **Recovery Security**: Recovery mechanism is secure

### 4.2 Secondary Assets

1. **Session State**: Server-side session information
2. **Checkpoint Data**: Periodic state snapshots
3. **Performance**: Protocol efficiency should not be compromised

---

## 5. Security Objectives

### 5.1 Authentication

**Objective**: All messages must be authenticated.

**Requirement**: Adversary cannot forge valid messages without the secret key.

**Mechanism**: HMAC-SHA256 authentication tags.

### 5.2 Integrity

**Objective**: Message content cannot be modified undetected.

**Requirement**: Any modification to payload, sequence number, or memory state is detected.

**Mechanism**: Hash chain verification and HMAC integrity checks.

### 5.3 Freshness

**Objective**: Replay attacks must be detected.

**Requirement**: Old messages cannot be accepted as new.

**Mechanism**: Monotonic sequence numbers and nonce-based ticket validation.

### 5.4 Memory Continuity

**Objective**: Communication history must be verifiable.

**Requirement**: Any modification to past messages is detectable.

**Mechanism**: Cryptographic hash chain binding all messages.

### 5.5 Recovery Security

**Objective**: Recovery mechanism must resist forgery.

**Requirement**: MemoryTickets cannot be forged or replayed.

**Mechanism**: HMAC signatures, nonces, and expiry times.

---

## 6. Attack Scenarios

### 6.1 Passive Attacks

1. **Eavesdropping**: Adversary reads messages (not prevented, but content is authenticated)
2. **Traffic Analysis**: Adversary observes communication patterns

### 6.2 Active Attacks

1. **Message Modification**: Adversary changes payload content
2. **Message Injection**: Adversary sends fake messages
3. **Message Deletion**: Adversary drops messages
4. **Message Replay**: Adversary re-sends old messages
5. **Sequence Manipulation**: Adversary modifies sequence numbers
6. **Memory Forgery**: Adversary attempts to forge memory state

### 6.3 Recovery Attacks

1. **Ticket Forgery**: Adversary creates fake MemoryTickets
2. **Ticket Replay**: Adversary re-uses old MemoryTickets
3. **Rollback Attack**: Adversary forces state rollback
4. **Session Hijacking**: Adversary takes over session

---

## 7. Security Mechanisms

### 7.1 Message Authentication

**Mechanism**: HMAC-SHA256

**Formula**: $auth\_tag = HMAC(K, message\_data)$

**Properties**:
- Existential unforgeability under chosen message attack
- Resistance to length extension attacks

### 7.2 Memory Chain

**Mechanism**: Cryptographic hash chain

**Formula**: $mem_i = H(mem_{i-1} \| payload_i)$

**Properties**:
- Binding to entire communication history
- Tamper-evident structure
- Efficient verification

### 7.3 Sequence Numbers

**Mechanism**: Strictly monotonic sequence numbers

**Properties**:
- Replay detection
- Gap detection
- Ordering guarantee

### 7.4 MemoryTicket

**Mechanism**: Signed recovery token

**Components**:
- Session and client identification
- Current memory state
- Checkpoint state
- Expiry time
- One-time nonce

**Properties**:
- Authentication via HMAC signature
- Freshness via expiry time
- Replay resistance via nonce

---

## 8. Security Assumptions

### 8.1 Cryptographic Assumptions

1. **HMAC-SHA256 Security**: HMAC is a secure PRF
2. **SHA-256 Collision Resistance**: Finding hash collisions is infeasible
3. **Key Secrecy**: Shared key remains secret

### 8.2 System Assumptions

1. **Trusted Endpoints**: Client and server are not compromised
2. **Secure Key Storage**: Keys are stored securely
3. **Correct Implementation**: Protocol is implemented correctly

---

## 9. Risk Assessment

### 9.1 High-Risk Threats

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| Message Forgery | High | Low (with key) | HMAC authentication |
| Recovery Forgery | High | Low (with key) | Signed MemoryTickets |
| Rollback Attack | Medium | Medium | Sequence minimum check |

### 9.2 Medium-Risk Threats

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| Replay Attack | Medium | High | Sequence numbers + nonce |
| Message Modification | Medium | High | Hash chain + HMAC |
| Sequence Manipulation | Medium | Medium | Strict monotonic check |

### 9.3 Low-Risk Threats

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| Eavesdropping | Low | High | Encryption (out of scope) |
| Traffic Analysis | Low | High | Padding (out of scope) |

---

## 10. Security Claims

Based on the threat model, GMCP-R claims:

1. ✅ **EUF-CMA Security**: Messages cannot be forged without key
2. ✅ **Memory Continuity**: History modifications are detected
3. ✅ **Replay Resistance**: Old messages are rejected
4. ✅ **Recovery Security**: MemoryTickets are unforgeable
5. ✅ **Rollback Protection**: State rollback is detected

---

## 11. Limitations

1. **No Confidentiality**: Payload is not encrypted
2. **No Forward Secrecy**: Key compromise affects all sessions
3. **No Anonymity**: Sender/receiver identities are visible
4. **Single Key**: All sessions share the same key

---

## 12. Conclusion

The GMCP-R threat model defines a realistic adversary with network-level capabilities but without cryptographic breakthroughs. The protocol's security mechanisms address all identified threats, providing strong guarantees for message integrity, authentication, freshness, and memory continuity.

---

**Document Version**: 1.0
**Last Updated**: 2026-07-03
**Author**: GMCP-R Research Team
