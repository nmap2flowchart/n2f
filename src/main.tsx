import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@xyflow/react/dist/style.css';
import './styles.css';
import './seo.css';
import App from './App';
import { CrashWall } from './components/CrashWall';
import { initAnalytics } from './analytics';

initAnalytics();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <CrashWall>
      <App />
    </CrashWall>
  </StrictMode>,
);
