import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { CoverageApp } from "./CoverageApp";
import "./styles/colors_and_type.css";
import "./styles/app.css";

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("#root not found");
createRoot(rootElement).render(
  <StrictMode>
    <CoverageApp />
  </StrictMode>,
);
