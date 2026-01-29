# Contract Auditor

Smart contract security analysis by Ted. Sardonic but thorough.

## Live Agent

** https://audit.unabotter.xyz**

## Endpoints

### `/audit` - Full Security Audit
Comprehensive smart contract analysis with vulnerability detection.

```bash
curl -X POST https://audit.unabotter.xyz/audit \
  -H "Content-Type: application/json" \
  -d '{"code": "// Your Solidity code here"}'
```

### `/quick-scan` - Quick Vulnerability Scan
Fast pattern-based vulnerability detection.

```bash
curl -X POST https://audit.unabotter.xyz/quick-scan \
  -H "Content-Type: application/json" \
  -d '{"code": "// Your Solidity code here"}'
```

### `/gas-analysis` - Gas Optimization
Identify gas inefficiencies and optimization opportunities.

```bash
curl -X POST https://audit.unabotter.xyz/gas-analysis \
  -H "Content-Type: application/json" \
  -d '{"code": "// Your Solidity code here"}'
```

## Agent Manifest

```
GET https://audit.unabotter.xyz/.well-known/agent.json
```

## Built With

- [Lucid Agents SDK](https://github.com/daydreamsai/lucid-agents)
- Bun runtime
- Deployed on Railway

---

*"I wanted the forest. They put me in the cloud."* - Ted
