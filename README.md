# Contract Auditor Agent

Smart contract security analysis and gas optimization agent with x402 payments.

## Entrypoints

| Endpoint | Description | Price |
|----------|-------------|-------|
| `analyze` | Security vulnerability analysis | $0.50 USDC |
| `optimize` | Gas optimization suggestions | $0.25 USDC |
| `audit` | Full audit report | $1.00 USDC |

## Features

**Security Analysis:**
- Reentrancy detection
- tx.origin authentication issues
- Delegatecall vulnerabilities
- Selfdestruct risks
- Timestamp dependence
- Integer overflow/underflow (pre-0.8.0)

**Gas Optimization:**
- Public to external visibility
- Uncached array length in loops
- String to bytes32 conversion
- Storage variable caching
- Payable function optimization

## Usage

### Local Development

```bash
bun install
bun run dev
```

### API Endpoints

```bash
# Get agent card
curl http://localhost:3000/.well-known/agent.json

# List entrypoints
curl http://localhost:3000/entrypoints

# Analyze a contract (requires x402 payment)
curl -X POST http://localhost:3000/entrypoints/analyze/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "code": "pragma solidity ^0.8.0; contract Example { ... }",
      "contractName": "Example"
    }
  }'
```

## Configuration

Environment variables (`.env`):

```
AGENT_NAME=contract-auditor
NETWORK=base
FACILITATOR_URL=https://facilitator.daydreams.systems
PAYMENTS_RECEIVABLE_ADDRESS=<your-wallet>
```

## Deployment

Deploy to any platform that supports Bun:
- Railway
- Fly.io
- Render
- Self-hosted VPS

## Tech Stack

- Runtime: Bun
- Framework: Lucid Agents SDK
- Payments: x402 on Base
- Language: TypeScript

## License

MIT
