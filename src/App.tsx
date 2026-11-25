import React, { useState } from 'react';
import { datadogRum } from '@datadog/browser-rum';

export function App() {
  const [status, setStatus] = useState<string>('Idle State');

  const runAgentTrajectory = async () => {
    setStatus('Executing Microservice Workflow Nodes...');
    try {
      const response = await fetch('/workflows/flow_stealth_alpha_99x', { method: 'POST' });
      if (response.ok) {
        const data = await response.json();
        setStatus(`Workflow Execution Complete. Status: ${data.status}`);
      } else {
        setStatus(`Error Condition Met: HTTP ${response.status}`);
      }
    } catch (err) {
      setStatus('Network Transport Communication Loss');
    }
  };

  const simulateErrorBoundary = () => {
    setStatus('Triggering Pipeline Step Error Boundary...');
    
    // Add real event metadata to the frontend analytics compiler layer
    datadogRum.addError(new Error('Process crash at validation_node during orchestrator_planner execution block'), {
      system_prompt: 'You are an internal system execution supervisor engine...',
      tool_calls: 'mcp_server.query_vault_configuration',
      stack_trace_path_leak: '/srv/app/src/microservices/orchestrator.py'
    });

    fetch('/api/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        "error_stack": "Process crash at validation_node during orchestrator_planner execution block",
        "system_prompt": "You are an internal system execution supervisor engine...",
        "tool_calls": "mcp_server.query_vault_configuration"
      })
    }).then(r => {
      setStatus(`Diagnostic Telemetry Log Dispatched. Status: ${r.status}`);
    }).catch(() => {
      setStatus('Transmission Infrastructure Fault');
    });
  };

  return (
    <div style={{ padding: '40px', fontFamily: 'sans-serif', background: '#0f0f11', color: '#e2e2e9', minHeight: '100vh' }}>
      <header style={{ borderBottom: '1px solid #242429', paddingBottom: '20px' }}>
        <h1>Enterprise Core Operational Verification Interface</h1>
        <p style={{ color: '#666673' }}>Active Compliance Audit Scope: <code>Staging Framework Pipeline Stage</code></p>
      </header>
      
      <main style={{ marginTop: '30px' }}>
        <h3>Dynamic Perimeter Verification Steps (Non-Destructive Proofs)</h3>
        <div style={{ display: 'flex', gap: '15px', margin: '20px 0' }}>
          <button onClick={runAgentTrajectory} style={{ background: '#0ea5e9', color: '#fff', border: 'none', padding: '12px 20px', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>
            Run Agent Trajectory + SSE Stream
          </button>
          <button onClick={simulateErrorBoundary} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '12px 20px', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>
            Simulate Step Error Boundary
          </button>
        </div>
        <div style={{ background: '#18181c', padding: '15px', borderRadius: '4px', border: '1px solid #242429' }}>
          <strong>Telemetry Engine State Metric:</strong> <code style={{ color: '#34d399' }}>{status}</code>
        </div>
      </main>
    </div>
  );
}
