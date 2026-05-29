import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { DeepInspectionApp } from "./DeepInspectionApp";
import "./styles/colors_and_type.css";
import "./styles/app.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("#root not found");
createRoot(rootEl).render(
  <StrictMode>
    <DeepInspectionApp />
  </StrictMode>,
);
