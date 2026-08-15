// lib/ghost_agent.js
// Backward-compatible entry point for passive landing-page analysis.
// The pooled implementation validates public targets, never fabricates network
// intelligence, and observes pages without clicking, typing, or submitting.

export { analyzeUrl } from './ghost_agent_pooled.js';
