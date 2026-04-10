import React from "react";
import ReactDOM from "react-dom/client";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { Dashboard } from "@/components/dashboard/dashboard";
import { StatusBar } from "@/components/status-bar";
import { CogwheelProvider } from "@/contexts/cogwheel-context";
import { Toaster } from "@/components/ui/sonner";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <CogwheelProvider>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset className="flex h-screen flex-col">
          <div className="flex-1 min-h-0">
            <Dashboard />
          </div>
          <StatusBar />
        </SidebarInset>
      </SidebarProvider>
      <Toaster />
    </CogwheelProvider>
  </React.StrictMode>,
);
