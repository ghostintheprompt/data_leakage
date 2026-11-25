import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import './index.css';
import { datadogRum } from '@datadog/browser-rum';

const win = window as any;
const config = win.__RUNTIME_CONFIG__ || {
  useProxy: false,
  clientToken: "pub_placeholder_token_abc123xyz789",
  sessionId: "sess_alpha_0001"
};

if (config.useProxy) {
  datadogRum.init({
    applicationId: 'db48c3b7-7e61-4609-b690-3dd304561081',
    clientToken: config.clientToken,
    site: 'datadoghq.com',
    service: 'enterprise-core-alpha',
    version: '1.0.0-staging-build',
    sessionSampleRate: 100,
    sessionReplaySampleRate: 100,
    trackUserInteractions: true,
    trackResources: true,
    trackLongTasks: true,
    defaultPrivacyLevel: 'mask-user-input',
    proxy: '/api/telemetry',
    beforeSend: (event) => {
      if (event.type === 'resource' && event.resource?.url?.includes('/workflows/')) {
        return false; 
      }
      return true;
    }
  });
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
