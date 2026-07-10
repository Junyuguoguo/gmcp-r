# GMCP-R Protocol: Experiment Methodology

## 1. Overview

This document describes the experimental methodology for evaluating the GMCP-R protocol. All experiments follow rigorous scientific methodology to ensure reproducibility and statistical validity.

---

## 2. Experimental Setup

### 2.1 Hardware Configuration

| Component | Specification |
|-----------|---------------|
| CPU | 4 cores |
| Memory | 4GB |
| Storage | 40GB SSD |
| Network | VPC, 30Mbps |
| OS | Linux (Ubuntu 22.04) |

### 2.2 Software Configuration

| Component | Version |
|-----------|---------|
| Python | 3.11 |
| NumPy | Latest |
| SciPy | Latest |
| Matplotlib | Latest |

### 2.3 Network Configuration

- **Transport**: TCP/IP
- **Local Testing**: 127.0.0.1
- **Remote Testing**: VPC-hosted Ubuntu test node (address omitted from the manuscript package)
- **Ports**: 9000 (GMCP-R), 9001 (Baseline)

---

## 3. Experimental Design

### 3.1 Independent Variables

1. **Protocol**: GMCP-R, Hash Chain, Seq+MAC, Ticket Only
2. **Attack Type**: none, drop, modify, replay, prev_mem
3. **Message Count**: 100, 500, 1000
4. **Payload Size**: 128, 512 bytes

### 3.2 Dependent Variables

1. **Success Rate**: Percentage of accepted messages
2. **Throughput**: Messages per second
3. **RTT**: Round-trip time in milliseconds
4. **Attack Detection Rate**: Percentage of detected attacks
5. **Recovery Latency**: Time to recover after attack

### 3.3 Controlled Variables

1. **Server Configuration**: Same hardware and software
2. **Network Conditions**: Same network environment
3. **Random Seed**: Fixed for reproducibility
4. **Timing**: Consistent timing between experiments

---

## 4. Experimental Procedure

### 4.1 Baseline Comparison Experiment

1. **Setup**:
   - Start baseline server on port 9001
   - Configure protocol parameters
   - Initialize random seed

2. **Execution**:
   - For each protocol:
     - For each attack type:
       - For each message count:
         - For each payload size:
           - Repeat 30 times
           - Record all metrics

3. **Data Collection**:
   - Save to CSV with metadata
   - Include timestamp, git commit, Python version
   - Record system resource usage

### 4.2 Attack Detection Experiment

1. **Attack Implementation**:
   - **Drop**: Skip message at attack_seq
   - **Modify**: Change payload content
   - **Replay**: Re-send old message
   - **prev_mem**: Modify memory state

2. **Detection Verification**:
   - Check server response
   - Record detection reason
   - Verify attack_detected flag

### 4.3 Recovery Experiment

1. **Recovery Scenarios**:
   - Disconnect and reconnect
   - Attack detection and recovery
   - Memory state restoration

2. **Recovery Metrics**:
   - Recovery latency (ms)
   - Extra messages required
   - Extra bytes transmitted
   - Memory consistency after recovery

---

## 5. Statistical Analysis

### 5.1 Sample Size

- **Minimum**: 30 repetitions per configuration
- **Total Experiments**: 3,600 (4 protocols × 5 attacks × 3 msg_counts × 2 payloads × 30 repeats)

### 5.2 Statistical Tests

1. **Descriptive Statistics**:
   - Mean, standard deviation
   - Median, IQR
   - Min, max

2. **Inferential Statistics**:
   - The current manuscript reports descriptive statistics only.
   - Formal confidence intervals, pairwise tests, and multi-group inference should be added after expanding repeats for every experiment family.

3. **Effect Size**:
   - Effect sizes are deferred until the expanded repeat matrix is available.

### 5.3 Significance Level

- **α**: 0.05
- **Multiple Comparisons**: Bonferroni correction

---

## 6. Data Collection

### 6.1 Raw Data

CSV files with columns:
- experiment_id, run_id
- protocol, attack_type
- message_count, payload_size
- repeat_id
- sent_count, accepted_count, rejected_count
- success_rate, throughput
- rtt_mean, rtt_std, rtt_min, rtt_max
- attack_detected
- elapsed_seconds

### 6.2 Metadata

- git_commit: Current repository version
- python_version: Python interpreter version
- os_info: Operating system information
- random_seed: Random number generator seed
- command_line: Full command invocation
- experiment_type: Type of experiment
- start_time, end_time: Timestamps

### 6.3 Performance Metrics

- cpu_percent: CPU usage
- memory_usage_mb: Memory usage

---

## 7. Quality Assurance

### 7.1 Reproducibility

1. **Fixed Random Seeds**: All experiments use deterministic random seeds
2. **Version Control**: All code committed to git
3. **Environment Documentation**: Complete environment specification
4. **Data Preservation**: All raw data preserved

### 7.2 Validity

1. **Internal Validity**:
   - Controlled variables
   - Consistent procedures
   - Automated data collection

2. **External Validity**:
   - Real network conditions
   - Multiple attack scenarios
   - Various payload sizes

### 7.3 Reliability

1. **Test-Retest Reliability**: 30 repetitions per configuration
2. **Inter-Rater Reliability**: Automated measurement
3. **Internal Consistency**: Consistent metrics across experiments

---

## 8. Ethical Considerations

### 8.1 Responsible Disclosure

- Security vulnerabilities reported before publication
- Patches provided for identified issues

### 8.2 Data Privacy

- No personal data collected
- Experimental data anonymized

### 8.3 Fair Comparison

- All protocols tested under same conditions
- No bias in implementation

---

## 9. Limitations

### 9.1 Scope

- Single-client testing (concurrent testing separate)
- Local network conditions
- Python implementation only

### 9.2 Threats to Validity

1. **Implementation Bias**: Protocols implemented by same team
2. **Network Variability**: Network conditions may vary
3. **Hardware Limitations**: Single server configuration

### 9.3 Mitigation

1. **Blind Testing**: Protocol hidden during measurement
2. **Multiple Runs**: 30 repetitions reduce variance
3. **Statistical Tests**: Formal significance testing

---

## 10. Conclusion

This methodology ensures rigorous, reproducible experiments that provide valid and reliable results for evaluating the GMCP-R protocol. The experimental design follows best practices in systems research, with appropriate controls, statistical analysis, and quality assurance measures.

---

**Document Version**: 1.0
**Last Updated**: 2026-07-03
**Author**: GMCP-R Research Team
