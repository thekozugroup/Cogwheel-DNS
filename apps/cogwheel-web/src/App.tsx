import React from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/layout/app-layout";
import { PageShell } from "@/components/app/page";
import { LoadingSkeleton } from "@/components/app/states";
import { OverviewScreen } from "@/routes/overview";

/**
 * Overview is bundled eagerly because it is the landing screen; every other
 * screen is split out so the appliance does not ship the editing surfaces to
 * someone who only wanted to check whether blocking is on.
 */
const ActivityScreen = React.lazy(() =>
  import("@/routes/activity").then((module) => ({ default: module.ActivityScreen })),
);
const DevicesScreen = React.lazy(() =>
  import("@/routes/devices").then((module) => ({ default: module.DevicesScreen })),
);
const ProtectionScreen = React.lazy(() =>
  import("@/routes/protection").then((module) => ({ default: module.ProtectionScreen })),
);
const SettingsScreen = React.lazy(() =>
  import("@/routes/settings").then((module) => ({ default: module.SettingsScreen })),
);

function ScreenFallback() {
  return (
    <PageShell>
      <LoadingSkeleton rows={3} variant="cards" />
      <LoadingSkeleton className="mt-8" rows={5} variant="table" />
    </PageShell>
  );
}

function Lazy({ children }: { children: React.ReactNode }) {
  return <React.Suspense fallback={<ScreenFallback />}>{children}</React.Suspense>;
}

export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />} path="/">
        <Route element={<OverviewScreen />} index />
        <Route
          element={
            <Lazy>
              <ActivityScreen />
            </Lazy>
          }
          path="activity"
        />
        <Route
          element={
            <Lazy>
              <DevicesScreen />
            </Lazy>
          }
          path="devices"
        />
        <Route
          element={
            <Lazy>
              <ProtectionScreen />
            </Lazy>
          }
          path="protection"
        />
        <Route
          element={
            <Lazy>
              <SettingsScreen />
            </Lazy>
          }
          path="settings"
        />
        <Route element={<Navigate replace to="/" />} path="*" />
      </Route>
    </Routes>
  );
}
