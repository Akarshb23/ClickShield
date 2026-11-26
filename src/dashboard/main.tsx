import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "../styles/globals.css";

const rootElement = document.getElementById("root");

if (!rootElement) {
  throw new Error(
    'ClickShield Dashboard: Could not find the root element with id="root".'
  );
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);