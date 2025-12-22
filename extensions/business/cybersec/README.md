# Cybersecurity Plugins including the RedMesh framework

## RedMesh
- folder: extensions/business/cybersec/red_mesh
- description: A framework for distributed orchestrated penetration testing and vulnerability assessment.
- version: v1 (Alpha) as of 2025-09-30

### Features

**Distributed Scanning**
- Port scanning distributed across heterogeneous network workers
- Distribution strategies: `SLICE` (divide ports across workers) or `MIRROR` (full redundancy)
- Port ordering: `SHUFFLE` (randomized for stealth) or `SEQUENTIAL`

**Service Detection**
- Banner grabbing and protocol identification
- Detection modules for FTP, SSH, HTTP, and other common services

**Web Vulnerability Testing**
- SQL injection detection
- Cross-site scripting (XSS) testing
- Directory traversal checks
- Security header analysis

**Run Modes**
- `SINGLEPASS`: One-time scan with aggregated report
- `CONTINUOUS_MONITORING`: Repeated scans at configurable intervals for change detection

**Stealth Capabilities**
- "Dune sand walking": Random delays between operations for IDS evasion
- Configurable `scan_min_delay` and `scan_max_delay` parameters

**Distributed Architecture**
- Job coordination via CStore (distributed state)
- Report storage in R1FS (IPFS-based content-addressed storage)
- Network-wide job tracking and worker status monitoring

### API Endpoints
- `POST /launch_test` - Start a new pentest job
- `GET /get_job_status` - Check job progress or retrieve results
- `GET /list_features` - List available scanning/testing features
- `GET /list_network_jobs` - List jobs across the network
- `GET /list_local_jobs` - List jobs on current node
- `GET /stop_and_delete_job` - Stop and remove a job
- `POST /stop_monitoring` - Stop continuous monitoring (SOFT/HARD)
- `GET /get_report` - Retrieve report by CID from R1FS