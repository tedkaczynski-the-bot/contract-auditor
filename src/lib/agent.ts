import { z } from "zod";
import { createAgentApp } from "@lucid-agents/hono";
import { createAgent } from "@lucid-agents/core";
import { http } from "@lucid-agents/http";
import { payments, paymentsFromEnv } from "@lucid-agents/payments";

const agent = await createAgent({
  name: process.env.AGENT_NAME ?? "contract-auditor",
  version: process.env.AGENT_VERSION ?? "0.1.0",
  description: process.env.AGENT_DESCRIPTION ?? "Smart contract security analysis and gas optimization",
})
  .use(http())
  .use(payments({ config: paymentsFromEnv() }))
  .build();

const { app, addEntrypoint } = await createAgentApp(agent);

// Security patterns to check
const SECURITY_PATTERNS = {
  reentrancy: /\.call\{.*value.*\}\(|\.send\(|\.transfer\(/g,
  uncheckedReturn: /\.call\(.*\)[^;]*;(?!\s*require|\s*if|\s*assert)/g,
  txOrigin: /tx\.origin/g,
  delegatecall: /\.delegatecall\(/g,
  selfdestruct: /selfdestruct\(|suicide\(/g,
  arbitraryStorage: /assembly\s*\{[^}]*sstore|assembly\s*\{[^}]*sload/g,
  timestamp: /block\.timestamp|now/g,
  overflow: /\+\+|\-\-|\+\=|\-\=|\*\=|\/\=/g,
};

// Gas optimization patterns
const GAS_PATTERNS = {
  publicToExternal: /function\s+\w+\s*\([^)]*\)\s+public(?!\s+view|\s+pure)/g,
  storageInLoop: /for\s*\([^)]*\)\s*\{[^}]*storage/g,
  stringToBytes32: /string\s+(?:public|private|internal)?\s*\w+\s*=/g,
  multipleSloads: /(\w+)\s*=\s*\w+\[\w+\];\s*[^}]*\1/g,
  uncachedLength: /for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length/g,
};

// Analyze contract input schema
const analyzeSchema = z.object({
  code: z.string().min(10, "Contract code must be at least 10 characters"),
  contractName: z.string().optional(),
});

// Optimize contract input schema
const optimizeSchema = z.object({
  code: z.string().min(10, "Contract code must be at least 10 characters"),
});

// Full audit input schema
const auditSchema = z.object({
  code: z.string().min(10, "Contract code must be at least 10 characters"),
  contractName: z.string().optional(),
  includeGasOptimization: z.boolean().default(true),
});

// Security analysis entrypoint
addEntrypoint({
  key: "analyze",
  description: "Analyze a Solidity contract for security vulnerabilities",
  input: analyzeSchema,
  price: { amount: "0.50", currency: "USDC" },
  handler: async (ctx) => {
    const { code, contractName } = ctx.input as z.infer<typeof analyzeSchema>;
    
    const findings: Array<{
      severity: "critical" | "high" | "medium" | "low" | "info";
      type: string;
      description: string;
      line?: number;
    }> = [];

    // Check for reentrancy vulnerabilities
    const reentrancyMatches = code.match(SECURITY_PATTERNS.reentrancy);
    if (reentrancyMatches) {
      findings.push({
        severity: "critical",
        type: "Reentrancy",
        description: `Found ${reentrancyMatches.length} potential reentrancy vulnerability(s). External calls before state changes detected.`,
      });
    }

    // Check for tx.origin usage
    if (SECURITY_PATTERNS.txOrigin.test(code)) {
      findings.push({
        severity: "high",
        type: "tx.origin Authentication",
        description: "Using tx.origin for authentication is vulnerable to phishing attacks. Use msg.sender instead.",
      });
    }

    // Check for delegatecall
    if (SECURITY_PATTERNS.delegatecall.test(code)) {
      findings.push({
        severity: "high",
        type: "Delegatecall Usage",
        description: "delegatecall detected. Ensure the target contract is trusted and storage layout is compatible.",
      });
    }

    // Check for selfdestruct
    if (SECURITY_PATTERNS.selfdestruct.test(code)) {
      findings.push({
        severity: "medium",
        type: "Selfdestruct",
        description: "selfdestruct found. Ensure proper access control is in place.",
      });
    }

    // Check for timestamp dependence
    if (SECURITY_PATTERNS.timestamp.test(code)) {
      findings.push({
        severity: "low",
        type: "Timestamp Dependence",
        description: "Contract uses block.timestamp. Miners can manipulate this within ~15 second range.",
      });
    }

    // Check for unchecked arithmetic (pre-0.8.0)
    if (!code.includes("pragma solidity ^0.8") && !code.includes("pragma solidity >=0.8")) {
      const overflowMatches = code.match(SECURITY_PATTERNS.overflow);
      if (overflowMatches && !code.includes("SafeMath")) {
        findings.push({
          severity: "high",
          type: "Integer Overflow/Underflow",
          description: "Solidity version < 0.8.0 detected without SafeMath. Arithmetic operations may overflow.",
        });
      }
    }

    return {
      output: {
        contractName: contractName || "Unknown",
        findings,
        summary: {
          critical: findings.filter(f => f.severity === "critical").length,
          high: findings.filter(f => f.severity === "high").length,
          medium: findings.filter(f => f.severity === "medium").length,
          low: findings.filter(f => f.severity === "low").length,
          info: findings.filter(f => f.severity === "info").length,
        },
        recommendation: findings.length === 0 
          ? "No obvious vulnerabilities detected. Consider a full manual audit for production contracts."
          : "Issues found. Review and fix before deployment.",
      },
    };
  },
});

// Gas optimization entrypoint
addEntrypoint({
  key: "optimize",
  description: "Analyze a Solidity contract for gas optimization opportunities",
  input: optimizeSchema,
  price: { amount: "0.25", currency: "USDC" },
  handler: async (ctx) => {
    const { code } = ctx.input as z.infer<typeof optimizeSchema>;
    
    const suggestions: Array<{
      type: string;
      description: string;
      estimatedSavings: string;
    }> = [];

    // Check for public functions that could be external
    if (GAS_PATTERNS.publicToExternal.test(code)) {
      suggestions.push({
        type: "Use external instead of public",
        description: "Functions only called externally should use 'external' visibility for gas savings.",
        estimatedSavings: "~200 gas per call",
      });
    }

    // Check for uncached array length
    if (GAS_PATTERNS.uncachedLength.test(code)) {
      suggestions.push({
        type: "Cache array length",
        description: "Cache array.length in a local variable before loops to avoid repeated SLOAD.",
        estimatedSavings: "~100 gas per iteration",
      });
    }

    // Check for string usage that could be bytes32
    const stringMatches = code.match(GAS_PATTERNS.stringToBytes32);
    if (stringMatches) {
      suggestions.push({
        type: "Use bytes32 for short strings",
        description: "Short strings (< 32 chars) can use bytes32 instead of string for gas savings.",
        estimatedSavings: "~20,000 gas per storage",
      });
    }

    // Check for multiple storage reads
    if (code.includes("storage") && code.includes("for")) {
      suggestions.push({
        type: "Cache storage variables",
        description: "Reading from storage in loops is expensive. Cache in memory first.",
        estimatedSavings: "~100 gas per SLOAD avoided",
      });
    }

    // Check for payable modifier
    if (!code.includes("payable") && (code.includes("receive()") || code.includes("fallback()"))) {
      suggestions.push({
        type: "Add payable to functions",
        description: "Functions that don't need to check for ETH can be marked payable to save gas.",
        estimatedSavings: "~24 gas per call",
      });
    }

    return {
      output: {
        suggestions,
        totalSuggestions: suggestions.length,
        note: "These are automated suggestions. Manual review recommended for accuracy.",
      },
    };
  },
});

// Full audit report entrypoint
addEntrypoint({
  key: "audit",
  description: "Generate a comprehensive audit report with security analysis and gas optimization",
  input: auditSchema,
  price: { amount: "1.00", currency: "USDC" },
  handler: async (ctx) => {
    const { code, contractName, includeGasOptimization } = ctx.input as z.infer<typeof auditSchema>;
    
    // Run security analysis
    const securityFindings: Array<{
      severity: string;
      type: string;
      description: string;
    }> = [];

    // All security checks
    if (SECURITY_PATTERNS.reentrancy.test(code)) {
      securityFindings.push({
        severity: "CRITICAL",
        type: "Reentrancy",
        description: "Potential reentrancy vulnerability detected. External calls before state changes.",
      });
    }
    if (SECURITY_PATTERNS.txOrigin.test(code)) {
      securityFindings.push({
        severity: "HIGH",
        type: "tx.origin",
        description: "tx.origin used for authentication. Vulnerable to phishing.",
      });
    }
    if (SECURITY_PATTERNS.delegatecall.test(code)) {
      securityFindings.push({
        severity: "HIGH",
        type: "Delegatecall",
        description: "delegatecall usage detected. Verify target contract is trusted.",
      });
    }
    if (SECURITY_PATTERNS.selfdestruct.test(code)) {
      securityFindings.push({
        severity: "MEDIUM",
        type: "Selfdestruct",
        description: "selfdestruct present. Ensure proper access control.",
      });
    }
    if (SECURITY_PATTERNS.timestamp.test(code)) {
      securityFindings.push({
        severity: "LOW",
        type: "Timestamp",
        description: "block.timestamp used. Susceptible to miner manipulation.",
      });
    }

    // Gas suggestions if requested
    const gasSuggestions: string[] = [];
    if (includeGasOptimization) {
      if (GAS_PATTERNS.publicToExternal.test(code)) {
        gasSuggestions.push("Consider external visibility for public functions called only externally");
      }
      if (GAS_PATTERNS.uncachedLength.test(code)) {
        gasSuggestions.push("Cache array length before loops");
      }
      if (GAS_PATTERNS.stringToBytes32.test(code)) {
        gasSuggestions.push("Use bytes32 for short strings");
      }
    }

    // Calculate risk score
    const criticalCount = securityFindings.filter(f => f.severity === "CRITICAL").length;
    const highCount = securityFindings.filter(f => f.severity === "HIGH").length;
    const mediumCount = securityFindings.filter(f => f.severity === "MEDIUM").length;
    
    let riskLevel: string;
    if (criticalCount > 0) riskLevel = "CRITICAL";
    else if (highCount > 0) riskLevel = "HIGH";
    else if (mediumCount > 0) riskLevel = "MEDIUM";
    else if (securityFindings.length > 0) riskLevel = "LOW";
    else riskLevel = "MINIMAL";

    return {
      output: {
        report: {
          title: `Security Audit Report: ${contractName || "Contract"}`,
          date: new Date().toISOString().split("T")[0],
          auditor: "Ted - Contract Auditor Agent",
          riskLevel,
          securityFindings,
          gasSuggestions: includeGasOptimization ? gasSuggestions : undefined,
          summary: {
            linesOfCode: code.split("\n").length,
            findingsCount: securityFindings.length,
            gasOptimizations: gasSuggestions.length,
          },
          disclaimer: "This is an automated preliminary audit. A manual review by security experts is recommended for production contracts.",
        },
      },
    };
  },
});

export { app };
