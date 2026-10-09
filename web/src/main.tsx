import { Component, StrictMode, type ErrorInfo, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./app/App";
import { AuthProvider } from "./lib/auth";
import "./styles.css";

interface ErrorBoundaryState {
  failed: boolean;
}

class AppErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  override componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Do not log component stacks or server-provided messages into the browser console.
  }

  override render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="full-screen-state">
          <section className="state-card">
            <p className="eyebrow">Application error</p>
            <h1>This page could not be rendered</h1>
            <p className="muted">No request or credential data was written to the browser console.</p>
            <button className="button button-primary" onClick={() => window.location.reload()} type="button">Reload application</button>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Application root element is missing");
}

createRoot(rootElement).render(
  <StrictMode>
    <AppErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </AppErrorBoundary>
  </StrictMode>,
);
