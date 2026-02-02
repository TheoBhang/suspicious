import React from "react";
import { createRoot } from "react-dom/client";

const mount = (elementId: string, node: React.ReactNode) => {
  const container = document.getElementById(elementId);
  if (!container) {
    return;
  }
  createRoot(container).render(node);
};

mount("app-root", <div />);
