// lib/syndicate_graph.js
// VerifyPulse Tier 2/3: Scam Syndicate Graph & Threat Cluster Correlation Engine
// Traces multi-node relationships between fraudulent UPI IDs, Phone Numbers, and Mule Accounts.

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

// Built-in seed intelligence for high-confidence Indian scam syndicates
const inMemorySyndicateClusters = [
  {
    clusterId: 'syn-dl-arrest-01',
    category: 'Digital Arrest / Fake Police Extortion',
    nodes: [
      'cbi.cybercell.verify@ybl',
      'mha.cyberdesk@icici',
      '+919876501234',
      '+919876501235'
    ],
    confidence: 98
  },
  {
    clusterId: 'syn-elec-bill-02',
    category: 'Electricity Bill Disconnection Scam',
    nodes: [
      'discom.billupdate@okaxis',
      'powerpay.officer@oksbi',
      '+917001234567',
      '+916009876543'
    ],
    confidence: 95
  },
  {
    clusterId: 'syn-loan-apk-03',
    category: 'Predatory Loan App Extortion Syndicate',
    nodes: [
      'instantrupee.settle@paytm',
      'fastcredit.loan@ybl',
      '+918800112233',
      '+919911223344'
    ],
    confidence: 99
  }
];

async function redisCommand(command, ...args) {
  if (!REDIS_URL || !REDIS_TOKEN) return null;
  try {
    const response = await fetch(REDIS_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${REDIS_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([command, ...args])
    });
    const data = await response.json();
    return data.result;
  } catch {
    return null;
  }
}

export async function querySyndicateGraph({ upi, phone, ifsc }) {
  const queryNodes = [];
  if (upi) queryNodes.push(String(upi).trim().toLowerCase());
  if (phone) {
    const cleanPhone = String(phone).replace(/\D/g, '');
    const core10 = cleanPhone.slice(-10);
    queryNodes.push(core10);
    queryNodes.push(`+91${core10}`);
  }

  // 1. Check Redis Threat Graph if configured
  if (REDIS_URL) {
    for (const node of queryNodes) {
      const clusterId = await redisCommand('GET', `threat:graph:node:${node}`);
      if (clusterId) {
        const clusterData = await redisCommand('GET', `threat:graph:cluster:${clusterId}`);
        const parsed = typeof clusterData === 'string' ? JSON.parse(clusterData) : clusterData;
        return {
          found: true,
          clusterId,
          matchedNode: node,
          category: parsed?.category || 'Organized Financial Scam Cluster',
          connectedNodes: parsed?.nodes || [node],
          confidence: parsed?.confidence || 95
        };
      }
    }
  }

  // 2. Query in-memory correlation graph
  for (const cluster of inMemorySyndicateClusters) {
    for (const queryNode of queryNodes) {
      const match = cluster.nodes.some(
        (n) => n.toLowerCase() === queryNode || n.replace(/\D/g, '').endsWith(queryNode)
      );
      if (match) {
        return {
          found: true,
          clusterId: cluster.clusterId,
          matchedNode: queryNode,
          category: cluster.category,
          connectedNodes: cluster.nodes.filter((n) => n.toLowerCase() !== queryNode),
          confidence: cluster.confidence
        };
      }
    }
  }

  return {
    found: false,
    clusterId: null,
    matchedNode: null,
    connectedNodes: []
  };
}
