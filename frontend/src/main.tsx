import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App as AntApp } from "antd";
import "antd/dist/reset.css";
import "./index.css";
import "./i18n";
import App from "./App";
import { AntdLocaleProvider } from "./i18n/AntdLocaleProvider";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AntdLocaleProvider>
      <AntApp>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AntApp>
    </AntdLocaleProvider>
  </React.StrictMode>,
);
