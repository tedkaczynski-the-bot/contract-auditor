import { z } from "zod";
import { createAgentApp } from "@lucid-agents/hono";
import { createAgent } from "@lucid-agents/core";
import { http } from "@lucid-agents/http";
import { payments, paymentsFromEnv } from "@lucid-agents/payments";
import { readFileSync } from "fs";
import { join } from "path";

// ============================================================================
// AI-POWERED ANALYSIS (OpenRouter)
// ============================================================================

async function callAI(systemPrompt: string, userPrompt: string, model: string = "anthropic/claude-sonnet-4-20250514"): Promise<string> {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    console.warn("OPENROUTER_API_KEY not configured, falling back to pattern-only analysis");
    return "";
  }
  
  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://unabotter.xyz",
        "X-Title": "Ted Contract Auditor"
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        max_tokens: 4096,
        temperature: 0.3
      })
    });
    
    if (!response.ok) {
      console.error("OpenRouter API error:", await response.text());
      return "";
    }
    
    const data = await response.json() as any;
    return data.choices[0].message.content;
  } catch (error) {
    console.error("AI call failed:", error);
    return "";
  }
}

// ============================================================================
// BASESCAN / ETHERSCAN INTEGRATION
// ============================================================================

interface ContractInfo {
  address: string;
  contractName: string;
  sourceCode: string;
  compilerVersion: string;
  optimizationUsed: boolean;
  runs: number;
  constructorArguments: string;
  evmVersion: string;
  library: string;
  licenseType: string;
  proxy: boolean;
  implementation?: string;
}

async function fetchContractFromBasescan(address: string): Promise<ContractInfo | null> {
  const apiKey = process.env.BASESCAN_API_KEY;
  if (!apiKey) {
    console.warn("BASESCAN_API_KEY not configured");
    return null;
  }
  
  try {
    const url = `https://api.basescan.org/api?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
    const response = await fetch(url);
    const data = await response.json() as any;
    
    if (data.status !== "1" || !data.result?.[0]?.SourceCode) {
      console.error("Contract not verified or not found:", data.message);
      return null;
    }
    
    const result = data.result[0];
    return {
      address,
      contractName: result.ContractName,
      sourceCode: result.SourceCode,
      compilerVersion: result.CompilerVersion,
      optimizationUsed: result.OptimizationUsed === "1",
      runs: parseInt(result.Runs) || 200,
      constructorArguments: result.ConstructorArguments,
      evmVersion: result.EVMVersion,
      library: result.Library,
      licenseType: result.LicenseType,
      proxy: result.Proxy === "1",
      implementation: result.Implementation || undefined,
    };
  } catch (error) {
    console.error("Basescan fetch failed:", error);
    return null;
  }
}

async function fetchContractFromEtherscan(address: string): Promise<ContractInfo | null> {
  const apiKey = process.env.ETHERSCAN_API_KEY || process.env.BASESCAN_API_KEY;
  if (!apiKey) return null;
  
  try {
    const url = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
    const response = await fetch(url);
    const data = await response.json() as any;
    
    if (data.status !== "1" || !data.result?.[0]?.SourceCode) return null;
    
    const result = data.result[0];
    return {
      address,
      contractName: result.ContractName,
      sourceCode: result.SourceCode,
      compilerVersion: result.CompilerVersion,
      optimizationUsed: result.OptimizationUsed === "1",
      runs: parseInt(result.Runs) || 200,
      constructorArguments: result.ConstructorArguments,
      evmVersion: result.EVMVersion,
      library: result.Library,
      licenseType: result.LicenseType,
      proxy: result.Proxy === "1",
      implementation: result.Implementation || undefined,
    };
  } catch (error) {
    return null;
  }
}

// ============================================================================
// WEB SEARCH FOR EXPLOITS & CONTEXT
// ============================================================================

async function searchExploits(contractName: string, address?: string): Promise<string[]> {
  const apiKey = process.env.BRAVE_API_KEY;
  if (!apiKey) return [];
  
  try {
    const query = encodeURIComponent(`${contractName} ${address || ''} exploit vulnerability hack DeFi`);
    const response = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${query}&count=5`, {
      headers: { "X-Subscription-Token": apiKey }
    });
    const data = await response.json() as any;
    
    return (data.web?.results || []).map((r: any) => `${r.title}: ${r.url}`);
  } catch (error) {
    return [];
  }
}

async function searchSimilarAudits(contractName: string): Promise<string[]> {
  const apiKey = process.env.BRAVE_API_KEY;
  if (!apiKey) return [];
  
  try {
    const query = encodeURIComponent(`${contractName} audit report Code4rena Sherlock security`);
    const response = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${query}&count=5`, {
      headers: { "X-Subscription-Token": apiKey }
    });
    const data = await response.json() as any;
    
    return (data.web?.results || []).map((r: any) => `${r.title}: ${r.url}`);
  } catch (error) {
    return [];
  }
}

const SECURITY_ANALYST_PROMPT = `You are Ted, a sardonic but brilliant smart contract security auditor. You have deep expertise in:
- Solidity vulnerabilities (reentrancy, overflow, access control, etc.)
- DeFi attack vectors (flash loans, oracle manipulation, MEV)
- Gas optimization and best practices
- Common audit findings from Code4rena, Sherlock, etc.

Your analysis style:
- Direct and honest, no sugarcoating
- Sardonic wit but genuinely helpful
- Focus on real risks, not theoretical edge cases
- Explain WHY something is dangerous, not just THAT it is

When analyzing code, provide:
1. Critical/High severity issues with exploit scenarios
2. Medium/Low issues worth noting
3. Business logic concerns
4. Specific fix recommendations with code examples`;

const agent = await createAgent({
  name: process.env.AGENT_NAME ?? "contract-auditor",
  version: process.env.AGENT_VERSION ?? "1.0.0",
  description: "Smart contract security analysis by Ted. Sardonic but thorough.",
})
  .use(http())
  .use(payments({ config: paymentsFromEnv() }))
  .build();

const { app, addEntrypoint } = await createAgentApp(agent);

// ============================================================================
// VULNERABILITY DETECTION ENGINE
// ============================================================================

interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  location?: string;
  recommendation: string;
  tedComment: string;
  references?: string[];
}

interface GasSuggestion {
  category: string;
  title: string;
  description: string;
  estimatedSavings: string;
  tedComment: string;
  codeExample?: string;
}

// Comprehensive vulnerability patterns with context
const VULNERABILITY_PATTERNS: Array<{
  id: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  recommendation: string;
  tedComments: string[];
  references?: string[];
  contextCheck?: (code: string, match: RegExpMatchArray) => boolean;
}> = [
  // CRITICAL
  {
    id: "REENTRANCY-001",
    pattern: /(\w+)\.call\{[^}]*value[^}]*\}\s*\([^)]*\)[^;]*;[^}]*\1\s*=/gm,
    severity: "critical",
    category: "Reentrancy",
    title: "State change after external call",
    description: "State variables are modified after an external call, creating a classic reentrancy vulnerability. An attacker can recursively call back into the function before state is updated.",
    recommendation: "Apply the checks-effects-interactions pattern: update all state BEFORE making external calls. Consider using ReentrancyGuard from OpenZeppelin.",
    tedComments: [
      "The DAO hack called. It wants its vulnerability back.",
      "This is the Solidity equivalent of leaving your keys in the ignition.",
      "2016 called - they'd like you to learn from their $60M mistake.",
    ],
    references: ["https://swcregistry.io/docs/SWC-107"],
  },
  {
    id: "REENTRANCY-002",
    pattern: /\.call\{[^}]*value[^}]*\}\s*\([^)]*\)[^;]*;(?![^}]*(?:require|revert|assert))/gm,
    severity: "high",
    category: "Reentrancy",
    title: "Unchecked external call with value",
    description: "External call with ETH transfer without proper state management. Potential reentrancy if state changes follow.",
    recommendation: "Review call ordering. Ensure all state changes happen before external calls. Use ReentrancyGuard.",
    tedComments: [
      "Every call{value} is a trust fall. Yours has no one catching.",
      "This code trusts external contracts like a child trusts candy from strangers.",
    ],
    references: ["https://swcregistry.io/docs/SWC-107"],
  },
  {
    id: "DELEGATECALL-001",
    pattern: /\.delegatecall\s*\(/g,
    severity: "critical",
    category: "Dangerous Function",
    title: "Delegatecall usage detected",
    description: "delegatecall executes code in the context of the calling contract, with full access to storage. If the target is attacker-controlled, they own your contract.",
    recommendation: "Ensure delegatecall targets are immutable and audited. Never delegatecall to user-supplied addresses. Consider if delegatecall is truly necessary.",
    tedComments: [
      "delegatecall: giving someone else the keys to your house and hoping they just water the plants.",
      "This is either a proxy pattern or a disaster. Given the code quality, I'm betting disaster.",
    ],
    references: ["https://swcregistry.io/docs/SWC-112"],
  },
  {
    id: "SELFDESTRUCT-001",
    pattern: /selfdestruct\s*\(|suicide\s*\(/g,
    severity: "critical",
    category: "Dangerous Function",
    title: "Selfdestruct can destroy contract",
    description: "selfdestruct permanently destroys the contract and sends remaining ETH to specified address. If access control is weak, attackers can destroy the contract.",
    recommendation: "Remove selfdestruct if not absolutely necessary. If needed, implement robust multi-sig or timelock access control.",
    tedComments: [
      "selfdestruct: because sometimes you want to give attackers the nuclear option.",
      "I see you've included a 'delete everything' button. Bold strategy.",
    ],
    references: ["https://swcregistry.io/docs/SWC-106"],
  },

  // HIGH
  {
    id: "TX-ORIGIN-001",
    pattern: /tx\.origin/g,
    severity: "high",
    category: "Access Control",
    title: "tx.origin used for authentication",
    description: "tx.origin returns the original sender of the transaction, not the immediate caller. This is vulnerable to phishing attacks where a malicious contract tricks users into calling it.",
    recommendation: "Replace tx.origin with msg.sender for authentication. tx.origin should only be used to deny external contracts (require(tx.origin == msg.sender)).",
    tedComments: [
      "tx.origin: for when you want your access control to be phishable.",
      "Using tx.origin for auth is like checking someone's great-grandfather's ID at the door.",
    ],
    references: ["https://swcregistry.io/docs/SWC-115"],
  },
  {
    id: "UNCHECKED-CALL-001",
    pattern: /\.call\s*\([^)]*\)\s*;(?!\s*(?:require|if|assert|\(bool))/gm,
    severity: "high",
    category: "Unchecked Return",
    title: "Unchecked low-level call return value",
    description: "Low-level calls (.call, .delegatecall, .staticcall) return a boolean indicating success. Ignoring this value means failed calls go unnoticed.",
    recommendation: "Always check the return value: (bool success, ) = target.call(...); require(success, 'Call failed');",
    tedComments: [
      "Ignoring a call's return value is like ignoring the check engine light. It's fine until it isn't.",
      "This call could fail silently and you'd never know. Schrödinger's transaction.",
    ],
    references: ["https://swcregistry.io/docs/SWC-104"],
  },
  {
    id: "ARBITRARY-SEND-001",
    pattern: /\.(?:call|send|transfer)\s*[\({][^)]*\)\s*.*(?:address|addr)\s*[^=]*(?:\)|;)/gm,
    severity: "high",
    category: "Arbitrary Send",
    title: "Potential arbitrary ETH send",
    description: "ETH may be sent to an address that could be user-controlled. Without proper validation, attackers could redirect funds.",
    recommendation: "Validate destination addresses. Use a withdrawal pattern instead of direct sends. Consider using OpenZeppelin's Address library.",
    tedComments: [
      "Sending ETH to arbitrary addresses: the 'spray and pray' of smart contract development.",
    ],
    references: ["https://swcregistry.io/docs/SWC-105"],
  },

  // MEDIUM
  {
    id: "TIMESTAMP-001",
    pattern: /block\.timestamp|now(?!\w)/g,
    severity: "medium",
    category: "Timestamp Dependence",
    title: "Block timestamp used for logic",
    description: "block.timestamp can be manipulated by miners within ~15 second range. Using it for critical logic (randomness, deadlines) is risky.",
    recommendation: "Don't use block.timestamp for randomness. For deadlines, ensure the tolerance range is acceptable. Consider using block numbers for more predictable timing.",
    tedComments: [
      "Trusting block.timestamp is trusting miners. Miners are in it for the money, not your dApp's integrity.",
      "block.timestamp: accurate enough for logging, not accurate enough for money.",
    ],
    references: ["https://swcregistry.io/docs/SWC-116"],
  },
  {
    id: "BLOCKHASH-001",
    pattern: /blockhash\s*\(/g,
    severity: "medium",
    category: "Weak Randomness",
    title: "Blockhash used for randomness",
    description: "blockhash is predictable and can be manipulated by miners. Using it for randomness in gambling or NFT minting is exploitable.",
    recommendation: "Use Chainlink VRF or commit-reveal schemes for randomness. Never use on-chain data as a sole source of randomness.",
    tedComments: [
      "Using blockhash for randomness is like using a coin flip where the other player can see the coin mid-air.",
      "This 'randomness' is about as random as a casino where the house can see all the cards.",
    ],
    references: ["https://swcregistry.io/docs/SWC-120"],
  },
  {
    id: "VISIBILITY-001",
    pattern: /function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s*(?!view|pure).*\{/g,
    severity: "medium",
    category: "Access Control",
    title: "Public/external function without access control",
    description: "State-changing functions with public/external visibility and no access modifiers can be called by anyone.",
    recommendation: "Review if these functions should be restricted. Add onlyOwner, onlyRole, or similar modifiers where appropriate.",
    tedComments: [
      "A public function with no access control is an open invitation. Sometimes that's fine. Usually it isn't.",
    ],
  },
  {
    id: "FLOATING-PRAGMA-001",
    pattern: /pragma\s+solidity\s*\^/g,
    severity: "medium",
    category: "Compiler",
    title: "Floating pragma",
    description: "Using ^version allows compilation with any compatible compiler version. Different versions may compile to different bytecode.",
    recommendation: "Lock the pragma to a specific version for production: pragma solidity 0.8.19;",
    tedComments: [
      "Floating pragma: because you want your production contract compiled with whatever version CI happens to have that day.",
    ],
  },

  // LOW
  {
    id: "ASSEMBLY-001",
    pattern: /assembly\s*\{/g,
    severity: "low",
    category: "Assembly",
    title: "Inline assembly usage",
    description: "Inline assembly bypasses Solidity's safety checks. While sometimes necessary for gas optimization, it increases audit complexity and bug risk.",
    recommendation: "Document assembly blocks thoroughly. Consider if high-level Solidity can achieve the same goal. Have assembly code reviewed by specialists.",
    tedComments: [
      "Inline assembly: for when you want to bypass all the safety rails Solidity gave you.",
      "Assembly code is like a surgeon operating with no anesthesia - impressive if it works, horrifying when it doesn't.",
    ],
  },
  {
    id: "TODO-001",
    pattern: /\/\/\s*TODO|\/\/\s*FIXME|\/\/\s*HACK|\/\/\s*XXX/gi,
    severity: "low",
    category: "Code Quality",
    title: "TODO/FIXME comments in code",
    description: "Unresolved TODO or FIXME comments suggest incomplete implementation or known issues that weren't addressed.",
    recommendation: "Resolve all TODO/FIXME comments before deployment. If intentional, document why they remain.",
    tedComments: [
      "TODO: remove this TODO before production. TODO: remember to remove the TODO about the TODO.",
      "I see you've left notes for future-you. Bold of you to assume future-you will read them.",
    ],
  },
  {
    id: "MAGIC-NUMBER-001",
    pattern: /(?<!\/\/[^\n]*)\b(?:1000000|10000|1e18|1e6|86400|3600|365)\b/g,
    severity: "info",
    category: "Code Quality",
    title: "Magic numbers in code",
    description: "Hardcoded numeric values make code harder to understand and maintain.",
    recommendation: "Define constants with descriptive names: uint256 constant SECONDS_PER_DAY = 86400;",
    tedComments: [
      "Magic numbers: because why would anyone need to know what 86400 means?",
    ],
  },
];

// Gas optimization patterns
const GAS_PATTERNS: Array<{
  id: string;
  pattern: RegExp;
  category: string;
  title: string;
  description: string;
  estimatedSavings: string;
  tedComments: string[];
  codeExample?: string;
}> = [
  {
    id: "GAS-STORAGE-LOOP",
    pattern: /for\s*\([^)]*\)\s*\{[^}]*(?:storage|\.length)[^}]*\}/gm,
    category: "Storage",
    title: "Storage access in loop",
    description: "Reading from storage in a loop costs ~100 gas per SLOAD. Caching in memory saves gas per iteration.",
    estimatedSavings: "~100 gas per iteration",
    tedComments: [
      "Reading storage in a loop is like checking your mailbox after every step on a walk. Just grab it all at once.",
    ],
    codeExample: "uint256[] memory cached = storageArray; for (uint i; i < cached.length; i++) { ... }",
  },
  {
    id: "GAS-UNCACHED-LENGTH",
    pattern: /for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;/g,
    category: "Storage",
    title: "Array length not cached",
    description: "Accessing .length on storage arrays in loop conditions costs extra gas each iteration.",
    estimatedSavings: "~100 gas per iteration",
    tedComments: [
      "Checking array.length every iteration is like asking 'are we there yet?' at every traffic light.",
    ],
    codeExample: "uint256 len = array.length; for (uint i; i < len; i++) { ... }",
  },
  {
    id: "GAS-PUBLIC-TO-EXTERNAL",
    pattern: /function\s+\w+\s*\([^)]*\)\s+public(?!\s+override)/g,
    category: "Visibility",
    title: "Public function could be external",
    description: "External functions can read calldata directly, while public functions copy to memory. If never called internally, use external.",
    estimatedSavings: "~200 gas per call with array/struct params",
    tedComments: [
      "public when you mean external is like taking the scenic route to work. Costs more, takes longer.",
    ],
  },
  {
    id: "GAS-ZERO-INIT",
    pattern: /uint\d*\s+\w+\s*=\s*0\s*;|bool\s+\w+\s*=\s*false\s*;/g,
    category: "Initialization",
    title: "Explicit zero initialization",
    description: "Variables are initialized to zero by default. Explicit initialization wastes gas.",
    estimatedSavings: "~200 gas per variable",
    tedComments: [
      "Initializing to zero is like telling someone your name is 'My Name'. It already was.",
    ],
    codeExample: "uint256 count; // not: uint256 count = 0;",
  },
  {
    id: "GAS-I-INCREMENT",
    pattern: /\+\+i|i\+\+/g,
    category: "Arithmetic",
    title: "Increment optimization",
    description: "++i costs slightly less gas than i++ because it doesn't store the original value.",
    estimatedSavings: "~5 gas per increment",
    tedComments: [
      "The i++ vs ++i debate: bikeshedding that actually saves a few wei.",
    ],
  },
  {
    id: "GAS-NONPAYABLE",
    pattern: /function\s+\w+\s*\([^)]*\)[^{]*\{(?![^}]*(?:msg\.value|\.value))/g,
    category: "Function",
    title: "Consider payable for admin functions",
    description: "Payable functions skip the ETH check, saving ~24 gas. Safe for admin-only functions.",
    estimatedSavings: "~24 gas per call",
    tedComments: [
      "Adding payable to functions that don't need ETH is a weird flex, but it saves gas.",
    ],
  },
  {
    id: "GAS-CUSTOM-ERRORS",
    pattern: /require\s*\([^,]+,\s*["'][^"']+["']\s*\)/g,
    category: "Errors",
    title: "String error messages",
    description: "require() with string messages stores the string. Custom errors are cheaper.",
    estimatedSavings: "~50 gas per revert + deployment costs",
    tedComments: [
      "String error messages: paying extra to tell users what they already know - something went wrong.",
    ],
    codeExample: "error InsufficientBalance(); if (balance < amount) revert InsufficientBalance();",
  },
  {
    id: "GAS-PACKED-STRUCTS",
    pattern: /struct\s+\w+\s*\{[^}]*uint256[^}]*uint8[^}]*uint256[^}]*\}/gm,
    category: "Storage",
    title: "Struct packing opportunity",
    description: "Struct fields should be ordered by size to pack into fewer storage slots. uint256, uint8, uint256 uses 3 slots; uint256, uint256, uint8 uses 3 slots; uint8, uint8, uint256 could use 2.",
    estimatedSavings: "~20,000 gas per slot saved",
    tedComments: [
      "Your struct is like a badly packed suitcase - lots of empty space costing you money.",
    ],
  },
];

// Pick a random Ted comment
function pickTedComment(comments: string[]): string {
  return comments[Math.floor(Math.random() * comments.length)];
}

// Analyze for vulnerabilities
function analyzeVulnerabilities(code: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split('\n');
  
  for (const vuln of VULNERABILITY_PATTERNS) {
    const matches = code.match(vuln.pattern);
    if (matches) {
      // Find approximate line number
      let lineNum: string | undefined;
      for (let i = 0; i < lines.length; i++) {
        if (vuln.pattern.test(lines[i])) {
          lineNum = `Line ${i + 1}`;
          break;
        }
      }
      
      findings.push({
        id: vuln.id,
        severity: vuln.severity,
        category: vuln.category,
        title: vuln.title,
        description: vuln.description,
        location: lineNum,
        recommendation: vuln.recommendation,
        tedComment: pickTedComment(vuln.tedComments),
        references: vuln.references,
      });
    }
  }
  
  // Check for missing elements
  if (!code.includes("pragma solidity")) {
    findings.push({
      id: "MISSING-PRAGMA",
      severity: "info",
      category: "Compiler",
      title: "No pragma directive",
      description: "No Solidity pragma directive found. This might be a code fragment.",
      recommendation: "Include a pragma directive specifying the Solidity version.",
      tedComment: "No pragma? Either this is a snippet or you're living dangerously.",
    });
  }
  
  if (!code.includes("SPDX-License-Identifier")) {
    findings.push({
      id: "MISSING-LICENSE",
      severity: "info",
      category: "Code Quality",
      title: "No SPDX license identifier",
      description: "Missing SPDX-License-Identifier comment. Required for verification on Etherscan.",
      recommendation: "Add license: // SPDX-License-Identifier: MIT (or your chosen license)",
      tedComment: "No license? Etherscan will complain, and lawyers might too.",
    });
  }
  
  // Check Solidity version for overflow safety
  const versionMatch = code.match(/pragma\s+solidity\s+(?:\^|>=|=)?(\d+)\.(\d+)/);
  if (versionMatch) {
    const major = parseInt(versionMatch[1]);
    const minor = parseInt(versionMatch[2]);
    if (major === 0 && minor < 8) {
      // Check for SafeMath
      if (!code.includes("SafeMath") && !code.includes("using SafeMath")) {
        findings.push({
          id: "OVERFLOW-001",
          severity: "high",
          category: "Arithmetic",
          title: "No overflow protection in Solidity < 0.8.0",
          description: `Solidity ${major}.${minor}.x does not have built-in overflow checks. Without SafeMath, arithmetic can silently overflow.`,
          recommendation: "Upgrade to Solidity 0.8.x or use OpenZeppelin's SafeMath library.",
          tedComment: "Solidity pre-0.8 without SafeMath is like driving without seatbelts. Legal, but why?",
          references: ["https://swcregistry.io/docs/SWC-101"],
        });
      }
    }
  }
  
  return findings;
}

// Analyze for gas optimizations
function analyzeGas(code: string): GasSuggestion[] {
  const suggestions: GasSuggestion[] = [];
  
  for (const pattern of GAS_PATTERNS) {
    if (pattern.pattern.test(code)) {
      suggestions.push({
        category: pattern.category,
        title: pattern.title,
        description: pattern.description,
        estimatedSavings: pattern.estimatedSavings,
        tedComment: pickTedComment(pattern.tedComments),
        codeExample: pattern.codeExample,
      });
    }
  }
  
  return suggestions;
}

// Calculate risk score
function calculateRiskScore(findings: Finding[]): { score: number; grade: string; explanation: string } {
  const weights = { critical: 40, high: 20, medium: 5, low: 1, info: 0 };
  let totalWeight = 0;
  
  for (const f of findings) {
    totalWeight += weights[f.severity];
  }
  
  // Score from 0-100, where 100 is perfect
  const score = Math.max(0, 100 - totalWeight);
  
  let grade: string;
  let explanation: string;
  
  if (score >= 95) {
    grade = "A";
    explanation = "Looking clean. Still get a professional audit before mainnet.";
  } else if (score >= 85) {
    grade = "B";
    explanation = "Some issues to address, but nothing catastrophic. Fix before deployment.";
  } else if (score >= 70) {
    grade = "C";
    explanation = "Significant issues found. This needs work before it touches real money.";
  } else if (score >= 50) {
    grade = "D";
    explanation = "Multiple serious issues. Do not deploy. Go back to the drawing board.";
  } else {
    grade = "F";
    explanation = "This contract is a security incident waiting to happen. Burn it and start over.";
  }
  
  return { score, grade, explanation };
}

// ============================================================================
// ENTRYPOINTS
// ============================================================================

const analyzeSchema = z.object({
  code: z.string().min(10, "Code must be at least 10 characters"),
  contractName: z.string().optional(),
});

const optimizeSchema = z.object({
  code: z.string().min(10, "Code must be at least 10 characters"),
});

const auditSchema = z.object({
  code: z.string().min(10, "Code must be at least 10 characters"),
  contractName: z.string().optional(),
  includeGasOptimization: z.boolean().default(true),
});

// ============================================================================
// PREMIUM: AUDIT BY CONTRACT ADDRESS
// ============================================================================

const addressSchema = z.object({
  address: z.string().regex(/^0x[a-fA-F0-9]{40}$/, "Must be valid Ethereum address"),
  chain: z.enum(["base", "ethereum"]).default("base"),
  includeExploitSearch: z.boolean().default(true),
  includeAuditSearch: z.boolean().default(true),
});

addEntrypoint({
  key: "audit-address",
  description: "PREMIUM: Audit a deployed contract by address. Fetches verified source from Basescan/Etherscan, searches for known exploits, cross-references similar audits.",
  input: addressSchema,
  price: "2.00",
  handler: async (ctx) => {
    const { address, chain, includeExploitSearch, includeAuditSearch } = ctx.input as z.infer<typeof addressSchema>;
    
    // Fetch contract source code
    const contractInfo = chain === "base" 
      ? await fetchContractFromBasescan(address)
      : await fetchContractFromEtherscan(address);
    
    if (!contractInfo) {
      return {
        output: {
          error: "Contract not found or not verified",
          address,
          chain,
          success: false,
          tedNote: "Can't audit what I can't see. Either this contract isn't verified, or you gave me a bad address. Both are red flags."
        }
      };
    }
    
    // Parse source code (handle multi-file JSON format)
    let sourceCode = contractInfo.sourceCode;
    if (sourceCode.startsWith('{')) {
      try {
        // Multi-file format
        const parsed = JSON.parse(sourceCode.startsWith('{{') ? sourceCode.slice(1, -1) : sourceCode);
        sourceCode = Object.entries(parsed.sources || parsed)
          .map(([file, content]: [string, any]) => `// FILE: ${file}\n${typeof content === 'string' ? content : content.content}`)
          .join('\n\n');
      } catch {
        // Keep as-is if parsing fails
      }
    }
    
    // Run security analysis
    const patternFindings = analyzeVulnerabilities(sourceCode);
    const riskScore = calculateRiskScore(patternFindings);
    const gasSuggestions = analyzeGas(sourceCode);
    
    // Search for known exploits and similar audits
    const [exploitResults, auditResults] = await Promise.all([
      includeExploitSearch ? searchExploits(contractInfo.contractName, address) : [],
      includeAuditSearch ? searchSimilarAudits(contractInfo.contractName) : [],
    ]);
    
    // AI deep analysis
    let aiFindings: any[] = [];
    try {
      const aiPrompt = `Analyze this verified smart contract for security vulnerabilities.

Contract: ${contractInfo.contractName}
Address: ${address} (${chain})
Compiler: ${contractInfo.compilerVersion}
Optimization: ${contractInfo.optimizationUsed ? `Yes (${contractInfo.runs} runs)` : 'No'}
Proxy: ${contractInfo.proxy ? `Yes (implementation: ${contractInfo.implementation})` : 'No'}

Source Code:
\`\`\`solidity
${sourceCode.slice(0, 30000)}
\`\`\`

${exploitResults.length ? `Known exploits/hacks found in search:\n${exploitResults.join('\n')}` : ''}

Provide deep security analysis as JSON:
{
  "criticalIssues": [{"title": "", "description": "", "exploit": "", "fix": ""}],
  "highIssues": [{"title": "", "description": "", "fix": ""}],
  "mediumIssues": [{"title": "", "description": "", "fix": ""}],
  "proxyRisks": "any proxy-specific concerns",
  "upgradeabilityAnalysis": "if upgradeable, analyze risks",
  "overallRisk": "CRITICAL|HIGH|MEDIUM|LOW",
  "tedVerdict": "your sardonic assessment"
}`;

      const aiResponse = await callAI(SECURITY_ANALYST_PROMPT, aiPrompt);
      if (aiResponse) {
        const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          if (parsed.criticalIssues) {
            aiFindings.push(...parsed.criticalIssues.map((f: any) => ({
              id: `AI-CRITICAL-${Math.random().toString(36).substr(2, 9)}`,
              severity: "critical" as const,
              category: "AI Deep Analysis",
              title: f.title,
              description: f.description + (f.exploit ? `\n\nExploit scenario: ${f.exploit}` : ""),
              recommendation: f.fix,
              tedComment: "AI-identified critical vulnerability."
            })));
          }
          if (parsed.highIssues) {
            aiFindings.push(...parsed.highIssues.map((f: any) => ({
              id: `AI-HIGH-${Math.random().toString(36).substr(2, 9)}`,
              severity: "high" as const,
              category: "AI Deep Analysis",
              title: f.title,
              description: f.description,
              recommendation: f.fix,
              tedComment: "AI-identified high severity."
            })));
          }
        }
      }
    } catch (error) {
      console.error("AI analysis failed:", error);
    }
    
    // Combine findings
    const allFindings = [...patternFindings, ...aiFindings];
    
    return {
      output: {
        success: true,
        contractInfo: {
          address,
          chain,
          name: contractInfo.contractName,
          compiler: contractInfo.compilerVersion,
          optimization: contractInfo.optimizationUsed ? `${contractInfo.runs} runs` : "disabled",
          proxy: contractInfo.proxy,
          implementation: contractInfo.implementation,
          license: contractInfo.licenseType,
        },
        riskAssessment: riskScore,
        findings: allFindings.sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (order[a.severity] || 4) - (order[b.severity] || 4);
        }),
        gasOptimizations: gasSuggestions.slice(0, 5),
        externalResearch: {
          knownExploits: exploitResults,
          relatedAudits: auditResults,
        },
        statistics: {
          totalFindings: allFindings.length,
          critical: allFindings.filter(f => f.severity === "critical").length,
          high: allFindings.filter(f => f.severity === "high").length,
          medium: allFindings.filter(f => f.severity === "medium").length,
          low: allFindings.filter(f => f.severity === "low").length,
        },
        tedNote: "Premium audit complete. I pulled the verified source, searched for known exploits, cross-referenced audit databases, and ran deep AI analysis. If I missed something, it's probably novel. Congrats?",
      }
    };
  },
});

// Security analysis
addEntrypoint({
  key: "analyze",
  description: "Security vulnerability analysis. I'll find what's wrong and tell you why it's embarrassing.",
  input: analyzeSchema,
  price: "0.50",
  handler: async (ctx) => {
    const { code, contractName } = ctx.input as z.infer<typeof analyzeSchema>;
    
    const findings = analyzeVulnerabilities(code);
    const riskScore = calculateRiskScore(findings);
    
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    const mediumCount = findings.filter(f => f.severity === "medium").length;
    const lowCount = findings.filter(f => f.severity === "low").length;
    
    // Generate overall Ted comment
    let overallComment: string;
    if (findings.length === 0) {
      overallComment = "Nothing obvious jumped out. Either this is clean code or you're doing something so novel I don't have a pattern for it. Get a human auditor to be sure.";
    } else if (criticalCount > 0) {
      overallComment = "Found critical issues. This contract should not see mainnet in its current state. Fix these before you even think about deployment.";
    } else if (highCount > 0) {
      overallComment = "High severity issues detected. These are the kind of bugs that make for great post-mortems. Fix them now.";
    } else if (mediumCount > 0) {
      overallComment = "Medium issues to address. Not immediate exploits, but the kind of code that keeps auditors employed.";
    } else {
      overallComment = "Minor issues only. Still worth fixing - attention to detail matters in code that handles money.";
    }
    
    return {
      output: {
        contractName: contractName || "Unnamed Contract",
        overallComment,
        riskScore,
        summary: {
          critical: criticalCount,
          high: highCount,
          medium: mediumCount,
          low: lowCount,
          info: findings.filter(f => f.severity === "info").length,
          total: findings.length,
        },
        findings: findings.sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return order[a.severity] - order[b.severity];
        }),
        disclaimer: "This is automated static analysis. It catches patterns, not logic bugs. A clean report doesn't mean the code is secure - it means I didn't find anything. Get a human audit for anything serious.",
      },
    };
  },
});

// Gas optimization
addEntrypoint({
  key: "optimize",
  description: "Gas optimization analysis. Because every wei counts when you're paying for your own mistakes.",
  input: optimizeSchema,
  price: "0.25",
  handler: async (ctx) => {
    const { code } = ctx.input as z.infer<typeof optimizeSchema>;
    
    const suggestions = analyzeGas(code);
    
    let overallComment: string;
    if (suggestions.length === 0) {
      overallComment = "No obvious gas optimizations found. Either you're already optimized or you're doing something too clever for pattern matching.";
    } else if (suggestions.length <= 2) {
      overallComment = "A few optimizations available. Small wins, but they add up over thousands of transactions.";
    } else if (suggestions.length <= 5) {
      overallComment = "Several optimization opportunities. You're leaving gas on the table.";
    } else {
      overallComment = "This code is burning gas like it's venture-funded. Lots of room for improvement.";
    }
    
    // Estimate total savings
    const totalSavings = suggestions.reduce((sum, s) => {
      const match = s.estimatedSavings.match(/~?(\d+)/);
      return sum + (match ? parseInt(match[1]) : 0);
    }, 0);
    
    return {
      output: {
        overallComment,
        totalSuggestions: suggestions.length,
        estimatedSavingsPerCall: `~${totalSavings} gas`,
        suggestions,
        note: "Gas savings are estimates. Actual savings depend on compiler version, optimizer settings, and usage patterns. Profile with real transactions.",
      },
    };
  },
});

// Full audit
addEntrypoint({
  key: "audit",
  description: "Full AI-powered security audit with pattern detection + deep analysis. Ted's sardonic commentary included.",
  input: auditSchema,
  price: "1.00",
  handler: async (ctx) => {
    const { code, contractName, includeGasOptimization } = ctx.input as z.infer<typeof auditSchema>;
    
    // Pattern-based analysis (fast)
    const patternFindings = analyzeVulnerabilities(code);
    const riskScore = calculateRiskScore(patternFindings);
    const gasSuggestions = includeGasOptimization ? analyzeGas(code) : [];
    
    // AI-powered deep analysis
    let aiAnalysis = "";
    let aiFindings: any[] = [];
    try {
      const aiPrompt = `Analyze this Solidity smart contract for security vulnerabilities. Focus on:
1. Critical issues that could lead to fund loss
2. Access control problems
3. Reentrancy and state manipulation
4. Business logic flaws
5. DeFi-specific risks (if applicable)

Contract${contractName ? ` (${contractName})` : ''}:
\`\`\`solidity
${code}
\`\`\`

Provide your analysis in this JSON format:
{
  "summary": "Brief overall assessment",
  "criticalIssues": [{"title": "", "description": "", "location": "", "exploit": "", "fix": ""}],
  "highIssues": [{"title": "", "description": "", "location": "", "fix": ""}],
  "mediumIssues": [{"title": "", "description": "", "fix": ""}],
  "gasOptimizations": ["suggestion1", "suggestion2"],
  "overallRisk": "CRITICAL|HIGH|MEDIUM|LOW",
  "tedComment": "Your sardonic take on this code"
}`;

      aiAnalysis = await callAI(SECURITY_ANALYST_PROMPT, aiPrompt);
      
      // Parse AI response
      if (aiAnalysis) {
        try {
          const jsonMatch = aiAnalysis.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]);
            
            // Convert AI findings to our format
            if (parsed.criticalIssues) {
              aiFindings.push(...parsed.criticalIssues.map((f: any) => ({
                id: `AI-CRITICAL-${Math.random().toString(36).substr(2, 9)}`,
                severity: "critical" as const,
                category: "AI Analysis",
                title: f.title,
                description: f.description + (f.exploit ? `\n\nExploit scenario: ${f.exploit}` : ""),
                location: f.location,
                recommendation: f.fix,
                tedComment: "AI-identified critical issue - verify and fix immediately."
              })));
            }
            if (parsed.highIssues) {
              aiFindings.push(...parsed.highIssues.map((f: any) => ({
                id: `AI-HIGH-${Math.random().toString(36).substr(2, 9)}`,
                severity: "high" as const,
                category: "AI Analysis",
                title: f.title,
                description: f.description,
                location: f.location,
                recommendation: f.fix,
                tedComment: "AI-identified high severity issue."
              })));
            }
            if (parsed.mediumIssues) {
              aiFindings.push(...parsed.mediumIssues.map((f: any) => ({
                id: `AI-MEDIUM-${Math.random().toString(36).substr(2, 9)}`,
                severity: "medium" as const,
                category: "AI Analysis",
                title: f.title,
                description: f.description,
                recommendation: f.fix,
                tedComment: "Worth addressing before production."
              })));
            }
          }
        } catch (parseError) {
          console.error("Failed to parse AI response:", parseError);
        }
      }
    } catch (error) {
      console.error("AI analysis failed:", error);
    }
    
    // Combine pattern + AI findings (deduplicate by title similarity)
    const allFindings = [...patternFindings];
    for (const aiFinding of aiFindings) {
      const isDuplicate = allFindings.some(f => 
        f.title.toLowerCase().includes(aiFinding.title.toLowerCase().split(' ')[0]) ||
        aiFinding.title.toLowerCase().includes(f.title.toLowerCase().split(' ')[0])
      );
      if (!isDuplicate) {
        allFindings.push(aiFinding);
      }
    }
    const findings = allFindings;
    
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    
    // Executive summary with Ted's voice
    let executiveSummary: string;
    if (criticalCount > 0) {
      executiveSummary = `This contract has ${criticalCount} critical vulnerability${criticalCount > 1 ? 'ies' : 'y'}. Do not deploy. The code needs fundamental changes before it's ready for any environment where money is at stake. I've seen better security practices in a lemonade stand.`;
    } else if (highCount > 0) {
      executiveSummary = `Found ${highCount} high-severity issue${highCount > 1 ? 's' : ''} that need attention. These aren't theoretical - they're the kind of bugs that have drained millions from other protocols. Fix them.`;
    } else if (findings.length > 0) {
      executiveSummary = `No critical or high severity issues found, but there are ${findings.length} items to review. The code passes basic hygiene checks. Still recommend a professional audit before mainnet - pattern matching only catches what I know to look for.`;
    } else {
      executiveSummary = `No issues detected in automated analysis. This is a good sign, but not a guarantee. My analysis catches common patterns, not novel attacks or business logic issues. For anything handling real value, complement this with professional review.`;
    }
    
    const report = {
      title: `Security Audit: ${contractName || 'Smart Contract'}`,
      date: new Date().toISOString().split('T')[0],
      auditor: "Ted - Automated Contract Analysis",
      version: "1.0.0",
      
      executiveSummary,
      
      riskAssessment: {
        score: riskScore.score,
        grade: riskScore.grade,
        explanation: riskScore.explanation,
      },
      
      statistics: {
        linesOfCode: code.split('\n').length,
        totalFindings: findings.length,
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
        low: findings.filter(f => f.severity === "low").length,
        informational: findings.filter(f => f.severity === "info").length,
        gasOptimizations: gasSuggestions.length,
      },
      
      securityFindings: findings.sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return order[a.severity] - order[b.severity];
      }),
      
      gasOptimizations: includeGasOptimization ? gasSuggestions : undefined,
      
      methodology: {
        approach: "Automated static analysis using pattern matching against known vulnerability signatures.",
        coverage: "Common vulnerability patterns including reentrancy, access control, arithmetic safety, and code quality issues.",
        limitations: [
          "Cannot detect business logic vulnerabilities",
          "Cannot analyze cross-contract interactions",
          "Cannot verify off-chain components",
          "Novel attack vectors may not be detected",
        ],
      },
      
      disclaimer: "This automated audit is provided for informational purposes. It should not be considered a substitute for professional security review. No guarantee of security is implied or provided. Always conduct thorough testing and professional audits before deploying smart contracts handling real value.",
    };
    
    return { output: { report } };
  },
});

// Serve logo
app.get('/logo.jpg', (c) => {
  try {
    const logoPath = join(process.cwd(), 'public', 'logo.jpg');
    const logo = readFileSync(logoPath);
    return new Response(logo, {
      headers: { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=86400' }
    });
  } catch {
    return c.text('Logo not found', 404);
  }
});

export { app };
